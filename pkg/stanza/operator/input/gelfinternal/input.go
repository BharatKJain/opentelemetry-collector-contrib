package gelfinternal

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/entry"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/helper"
)

// Syslog severity levels
var severityMapping = [...]entry.Severity{
	0: entry.Fatal,
	1: entry.Error3,
	2: entry.Error2,
	3: entry.Error,
	4: entry.Warn,
	5: entry.Info2,
	6: entry.Info,
	7: entry.Debug,
}

const (
	ChunkSize        = 1420
	chunkedHeaderLen = 12
	chunkedDataLen   = ChunkSize - chunkedHeaderLen
	chunkHeaderSize  = 12
)

var (
	magicChunked = []byte{0x1e, 0x0f}
	magicZlib    = []byte{0x78}
	magicGzip    = []byte{0x1f, 0x8b}
)

type Input struct {
	helper.InputOperator
	wg                        sync.WaitGroup
	cancel                    context.CancelFunc
	address                   string
	protocol                  string
	conn                      net.PacketConn
	udpMessageQueue           chan UDPMessage
	wgReader                  sync.WaitGroup
	wgProcessor               sync.WaitGroup
	asyncReaders              int
	asyncProcessors           int
	enableShortAndFullMessage bool
	enableGELFRawMessage      bool
	attributePrefix           string

	buffer     map[string]*MapGelfMessage
	lastBuffer map[string]*MapGelfMessage
	lastSwap   time.Time
	muBuffer   sync.Mutex
}

type GELFSegment struct {
	Id             string
	SequenceNumber int
	TotalCount     int
	Data           []byte
}

type UDPMessage struct {
	length int
	buffer []byte
	addr   net.Addr
}

type MapGelfMessage struct {
	stored   int
	segments [128][]byte
}

// Convert any type of attribute to string,
// at the log site, as well as any fields accumulated on the logger.
func (gelfRcvInput *Input) convertAnyToString(messsage *map[string]interface{}, key *string) string {
	var attributeValue string
	var stringTypeOfAttribute string
	value, ok := (*messsage)[*key]
	if !ok {
		gelfRcvInput.Logger().Error("Key not found in message", zap.String("Key: ", *key))
		return ""
	}

	// check if the value is nil, extracted value is set to null in the json
	if value == nil {
		return "null"
	}

	typeOfAttribute := reflect.TypeOf(value)
	if typeOfAttribute != nil {
		stringTypeOfAttribute = typeOfAttribute.String()
	} else {
		gelfRcvInput.Logger().Error("Failed to get type of attribute", zap.String("Key: ", *key))
		return ""
	}
	gelfRcvInput.Logger().Debug("Type of attribute with key", zap.String("Type: ", stringTypeOfAttribute), zap.String("Key: ", *key))
	switch stringTypeOfAttribute {
	case "string":
		attributeValue = value.(string)
	case "float", "float64":
		attributeValue = strconv.FormatFloat(value.(float64), 'g', -1, 64)
	case "float32":
		attributeValue = strconv.FormatFloat(float64(value.(float32)), 'g', -1, 32)
	case "int", "int32", "int64":
		attributeValue = strconv.Itoa(value.(int))
	case "bool":
		attributeValue = strconv.FormatBool(value.(bool))
	default:
		gelfRcvInput.Logger().Error("Failed to convert attribute value to string", zap.String("Key: ", *key), zap.String("type: ", stringTypeOfAttribute))

		return ""
	}
	return attributeValue
}

// Start will start listening for messages on a socket.
func (gelfRcvInput *Input) Start(_ operator.Persister) error {
	ctx, cancel := context.WithCancel(context.Background())
	gelfRcvInput.cancel = cancel

	udpAddr, err := net.ResolveUDPAddr(gelfRcvInput.protocol, gelfRcvInput.address)
	if err != nil {
		return fmt.Errorf("ResolveUDPAddr('%s'): %s", gelfRcvInput.address, err)
	}

	conn, err := net.ListenUDP(gelfRcvInput.protocol, udpAddr)
	if err != nil {
		gelfRcvInput.Logger().Error("Failed to open connection", zap.Error(err))
		return fmt.Errorf("failed to open connection: %w", err)
	}

	gelfRcvInput.Logger().Info("Started GELF UDP server")

	gelfRcvInput.conn = conn

	go gelfRcvInput.startReading(ctx)

	gelfRcvInput.Logger().Debug("Exiting the _Start function")

	return nil
}

// Stop will stop listening for udp messages.
func (gelfRcvInput *Input) Stop() error {
	if gelfRcvInput.cancel == nil {
		return nil
	}
	gelfRcvInput.cancel()
	gelfRcvInput.conn.Close()
	gelfRcvInput.Logger().Info("Stopping GELF server")
	gelfRcvInput.wg.Wait()
	close(gelfRcvInput.udpMessageQueue)

	return nil
}

// GELF code
// https://github.com/Graylog2/go-gelf/blob/master/gelf/gelf.go

func (gelfRcvInput *Input) GelfNewReader(addr string) error {
	var err error
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("ResolveUDPAddr('%s'): %s", addr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("ListenUDP: %s", err)
	}
	gelfRcvInput.conn = conn
	return nil
}

func (gelfRcvInput *Input) startReading(ctx context.Context) {
	for n := 0; n < gelfRcvInput.asyncReaders; n++ {
		gelfRcvInput.wgReader.Add(1)
		go gelfRcvInput.ReadUDPBufferAsync(ctx)
		gelfRcvInput.Logger().Debug("Started read workers...")
	}
	for n := 0; n < gelfRcvInput.asyncProcessors; n++ {
		gelfRcvInput.wgProcessor.Add(1)
		go gelfRcvInput.processMessagesAsync(ctx)
		gelfRcvInput.Logger().Debug("Started processor workers...")
	}
}

func (gelfRcvInput *Input) ReadUDPBufferAsync(ctx context.Context) {

	defer gelfRcvInput.wgReader.Done()

	for {

		var (
			n    int
			err  error
			addr net.Addr
		)
		buf := make([]byte, ChunkSize)

		n, addr, err = gelfRcvInput.conn.ReadFrom(buf)

		gelfRcvInput.Logger().Debug("Received message from UDP")

		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				gelfRcvInput.Logger().Error("Failed reading messages", zap.Error(err))
			}

			break
		}

		udpMessage := UDPMessage{
			addr:   addr,
			length: n,
			buffer: buf[:n],
		}

		// Send message to udp queue
		gelfRcvInput.udpMessageQueue <- udpMessage
	}
}

func (gelfRcvInput *Input) processMessagesAsync(ctx context.Context) {

	defer gelfRcvInput.wgProcessor.Done()

	for {
		// Read a message from the message queue.
		message, ok := <-gelfRcvInput.udpMessageQueue
		gelfRcvInput.Logger().Debug("Received queued message!")
		if !ok {
			return // Channel closed, exit the goroutine.
		}

		gelfRcvInput.Logger().Debug("Received message from UDP - entering Handling gelf message")
		gelfRcvInput.HandleGELFMessage(ctx, message.buffer, message.length)
	}
}

func (gelfRcvInput *Input) HandleGELFMessage(ctx context.Context, packet []byte, n int) {

	// Check if the packet is a chunked message or a full message
	if bytes.Equal(packet[:2], magicChunked) {
		segment := GELFSegment{
			Id:             string(packet[2:10]),
			SequenceNumber: int(packet[10]),
			TotalCount:     int(packet[11]),
			Data:           append(make([]byte, 0, n-len(packet)), packet[chunkedHeaderLen:]...),
		}

		gelfRcvInput.handleChunkedMessage(ctx, &segment, n) // Handle as a chunked message
	} else {
		gelfRcvInput.submitLog(ctx, packet) // Handle as a full message
	}
}

// handleChunkedMessage processes a chunked GELF message
func (gelfRcvInput *Input) handleChunkedMessage(ctx context.Context, gelfSegment *GELFSegment, n int) {

	gelfRcvInput.muBuffer.Lock()
	defer gelfRcvInput.muBuffer.Unlock()

	// Condition for checking 5 seconds by comparing with last_swap, clear last_buffer and swap current buffer with last_buffer
	// Took inspiration from Tremor's gelf_chunking implementation: https://github.com/tremor-rs/tremor-runtime/blob/main/tremor-interceptor/src/preprocessor/gelf_chunking.rs
	if time.Since(gelfRcvInput.lastSwap) > 5*time.Second {
		gelfRcvInput.lastSwap = time.Now()
		gelfRcvInput.lastBuffer = gelfRcvInput.buffer
		gelfRcvInput.buffer = make(map[string]*MapGelfMessage)
		gelfRcvInput.Logger().Debug("Swapped buffers!")
	}

	// If segment exists in last_buffer then process in that.
	gelfMessage, segmentExists := gelfRcvInput.lastBuffer[gelfSegment.Id]

	if segmentExists {
		if len(gelfMessage.segments[gelfSegment.SequenceNumber]) == 0 {
			// If the sequenceNumber is available then add
			if (gelfSegment.SequenceNumber >= 0) && (gelfSegment.SequenceNumber < gelfSegment.TotalCount) {
				// gelfRcvInput.lastBuffer[gelfSegment.Id] = ni

				gelfMessage.segments[gelfSegment.SequenceNumber] = gelfSegment.Data

				gelfMessage.stored++

				gelfRcvInput.Logger().Debug("last_buffer details", zap.Int("Stored in last_buffer: ", gelfMessage.stored), zap.Int("Total count in last_buffer: ", gelfSegment.TotalCount))

				if gelfMessage.stored == gelfSegment.TotalCount {

					var completeLogBytes []byte
					for i := 0; i < gelfSegment.TotalCount; i++ {
						completeLogBytes = append(completeLogBytes, gelfMessage.segments[i]...)
					}

					gelfRcvInput.submitLog(ctx, completeLogBytes)

					// Discarding the chunk even if the
					delete(gelfRcvInput.lastBuffer, gelfSegment.Id)
				}

			} else {
				// if sequence number is not present in segment's range then log error and discard the key from map
				gelfRcvInput.Logger().Error("Discarding out of range chunk")
				delete(gelfRcvInput.lastBuffer, gelfSegment.Id)
			}
		} else {
			gelfRcvInput.Logger().Error("Duplicate index in segment")
		}
	} else {
		// if segment is not present in last_buffer then check current_buffer
		gelfMessage, segmentExists := gelfRcvInput.buffer[gelfSegment.Id]
		if segmentExists {
			if len(gelfMessage.segments[gelfSegment.SequenceNumber]) == 0 {
				// If the sequenceNumber is available then add
				if (gelfSegment.SequenceNumber >= 0) && (gelfSegment.SequenceNumber < gelfSegment.TotalCount) {
					// gelfRcvInput.lastBuffer[gelfSegment.Id] = ni
					gelfMessage.segments[gelfSegment.SequenceNumber] = gelfSegment.Data

					gelfMessage.stored++

					gelfRcvInput.Logger().Debug("current_buffer details", zap.Int("Stored in last_buffer: ", gelfMessage.stored), zap.Int("Total count in last_buffer: ", gelfSegment.TotalCount))

					if gelfMessage.stored == gelfSegment.TotalCount {

						var completeLogBytes []byte
						for i := 0; i < gelfSegment.TotalCount; i++ {
							completeLogBytes = append(completeLogBytes, gelfMessage.segments[i]...)
						}

						gelfRcvInput.submitLog(ctx, completeLogBytes)

						delete(gelfRcvInput.lastBuffer, gelfSegment.Id)
					}

				} else {
					// if sequence number is not present in segment's range then log error and discard the key from map
					gelfRcvInput.Logger().Error("Discarding out of range chunk")
					delete(gelfRcvInput.lastBuffer, gelfSegment.Id)
				}
			} else {
				gelfRcvInput.Logger().Error("Duplicate index in segment")
			}
		} else {
			// if segment is not present in current_buffer then add to current_buffer map
			newGelfMessage := MapGelfMessage{
				stored:   0,
				segments: [128][]byte{},
			}

			newGelfMessage.segments[gelfSegment.SequenceNumber] = gelfSegment.Data

			newGelfMessage.stored++

			gelfRcvInput.buffer[gelfSegment.Id] = &newGelfMessage
		}
	}
}

func (gelfRcvInput *Input) submitLog(ctx context.Context, data []byte) {

	var entry *entry.Entry

	var err error

	message, err := gelfRcvInput.extractLogMessage(ctx, data)
	gelfRcvInput.Logger().Debug("Decompressed GELF ", zap.Any(" message: ", message))
	if err != nil {
		gelfRcvInput.Logger().Error("Error during decompression(non-chunked)", zap.Error(err))
		return // Discard the message
	} else {
		// handle log message
		if val, ok := message["short_message"].(string); ok {
			entry, err = gelfRcvInput.NewEntry(string(val))
			if err != nil {
				gelfRcvInput.Logger().Error("Error creating short_message log entry", zap.Error(err))
				return
			}
		} else if val, ok := message["full_message"].(string); ok {
			entry, err = gelfRcvInput.NewEntry(string(val))
			if err != nil {
				gelfRcvInput.Logger().Error("Error creating full_message log entry", zap.Error(err))
				return
			}
		}

		// handle enableGELFRawMessage
		if gelfRcvInput.enableGELFRawMessage {
			jsonData, err := json.Marshal(message)
			if err != nil {
				gelfRcvInput.Logger().Error("Error marshalling GELF raw message", zap.Error(err))
			} else {
				entry.AddAttribute(gelfRcvInput.attributePrefix+"raw_message", string(jsonData))
			}
		}

		// handle standard attributes
		// standard attributes - host, level, timestamp, level, facility
		standardAttributes := []string{"version", "host", "timestamp", "level", "facility", "line", "file"}
		standardAttributesWithMessage := []string{"version", "host", "timestamp", "level", "facility", "line", "file", "short_message", "full_message"}

		var attributes []string

		if gelfRcvInput.enableShortAndFullMessage {
			attributes = standardAttributesWithMessage
		} else {
			attributes = standardAttributes
		}

		for _, attribute := range attributes {

			if _, ok := message[attribute]; ok {
				attributeStringValue := gelfRcvInput.convertAnyToString(&message, &attribute)
				entry.AddAttribute(gelfRcvInput.attributePrefix+attribute, attributeStringValue)
				switch attribute {
				case "timestamp":
					// TODO: Find a way to check for type of timestamp instead of assuming it to be float64
					typeOfAttribute := reflect.TypeOf(message[attribute])
					if typeOfAttribute == nil {
						gelfRcvInput.Logger().Error("Failed to get type of attribute for timestamp")
						return
					}
					switch typeOfAttribute.String() {
					case "float", "float64":
						entry.ObservedTimestamp = time.Unix(int64(message[attribute].(float64)), 0)
						entry.Timestamp = time.Unix(int64(message[attribute].(float64)), 0)
					case "int", "int32", "int64":
						entry.ObservedTimestamp = time.Unix(int64(message[attribute].(int)), 0)
						entry.Timestamp = time.Unix(int64(message[attribute].(int)), 0)
					}
				case "level":
					entry.Severity = severityMapping[int(message[attribute].(float64))]
				}
			} else {
				gelfRcvInput.Logger().Debug("Attribute not found", zap.String("Attribute: ", attribute))
			}
		}

		// handle non-standard/additional attributes starting with "_"
		for k := range message {
			// Check if key starts with "_" then add to additional attributes, for example _application
			if string(k[0]) == "_" {
				attributeStringValue := gelfRcvInput.convertAnyToString(&message, &k)
				entry.AddAttribute(gelfRcvInput.attributePrefix+k, attributeStringValue)
				// gelfRcvInput.Logger().Debug("Additional attributes", zap.String("Key: ", k), zap.Any("Value: ", v))
			}
		}

		err := gelfRcvInput.Write(ctx, entry)
		if err != nil {
			gelfRcvInput.Logger().Error("Error writing log entry", zap.Error(err))
		}

	}

}

func (gelfRcvInput *Input) extractLogMessage(ctx context.Context, data []byte) (map[string]interface{}, error) {

	var decompressedDataReader io.ReadCloser
	var reader io.Reader
	var noCompression = false
	var err error

	// Check the compression type and decompress accordingly
	if bytes.HasPrefix(data, magicGzip) {
		decompressedDataReader, err = gzip.NewReader(bytes.NewReader(data))
	} else if bytes.HasPrefix(data, magicZlib) &&
		(int(data[0])*256+int(data[1]))%31 == 0 {
		decompressedDataReader, err = zlib.NewReader(bytes.NewReader(data))
	} else {
		reader = bytes.NewReader(data) // No compression
		noCompression = true
	}

	if err != nil {
		gelfRcvInput.Logger().Error("Error decompressing packet", zap.Error(err))
		return nil, err
	}

	// Write the decompressed message
	var gelfLogEntryRaw map[string]interface{}

	if noCompression {
		if err := json.NewDecoder(reader).Decode(&gelfLogEntryRaw); err != nil {
			return nil, fmt.Errorf("json.Unmarshal: %s", err)
		}
	} else {
		if err := json.NewDecoder(decompressedDataReader).Decode(&gelfLogEntryRaw); err != nil {
			return nil, fmt.Errorf("json.Unmarshal: %s", err)
		}

		decompressedDataReader.Close()
	}

	return gelfLogEntryRaw, nil
}
