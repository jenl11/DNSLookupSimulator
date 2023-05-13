package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.IntStream;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;

    // The offset into the message where the header ends and the data begins.
    public final static int DataOffset = 12;

    // Opcode for a standard query
    public final static int QUERY = 0;

    /**
     * TODO:  You will add additional constants and fields
     */
    private final ByteBuffer buffer;
    private final Map<String, Integer> strPosition = new HashMap<>();




    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */
    public DNSMessage(short id) {
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
        // TODO: Complete this method\
        setID(id);
        buffer.position(12);
    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        buffer = ByteBuffer.wrap(recvd, 0, length);
        // TODO: Complete this method
        buffer.position(12);

    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
     * TODO:  They are all to be completed
     */
    public int getID() {
        return buffer.getShort(0) & 0xFFFF;
    }

    public void setID(int id) {
        buffer.putShort(0, (short) id);
    }

    public boolean getQR() {
        return (buffer.get(2) & 0x80) != 0;
    }

    public void setQR(boolean qr) {
        byte val = buffer.get(2);
        if (qr) {
            buffer.put(2, (byte) (val | 0x80));
        } else {
            buffer.put(2, (byte) (val & 0x7F));
        }
    }

    public boolean getAA() {
        return (buffer.get(2) & 0x04) != 0;
    }

    public void setAA(boolean aa) {
        byte val = buffer.get(2);
        if (aa) {
            buffer.put(2, (byte) (val | 0x04));
        } else {
            buffer.put(2, (byte) (val & 0xFB));
        }
    }

    public int getOpcode() {
//        System.out.println(buffer.get(2));
//        System.out.println((buffer.get(2) & 0x78) >> 3);

        return (buffer.get(2) & 0x78) >> 3;
    }

    public void setOpcode(int opcode) {
        byte val = buffer.get(2);
//        System.out.println((pos & 0x87));
//        System.out.println(opcode << 3);
//        System.out.println(((pos & 0x87) | opcode << 3));

        buffer.put(2, (byte) ((val & 0x87) | opcode << 3));
    }

    public boolean getTC() {
        return (buffer.get(2) & 0x02) != 0;
    }

    public void setTC(boolean tc) {
        byte val = buffer.get(2);
        if (tc) {
            buffer.put(2, (byte) (val | 0x02));
        } else {
            buffer.put(2, (byte) (val & 0xFD));
        }
    }

    public boolean getRD() {
        return (buffer.get(2) & 0x01) != 0;
    }

    public void setRD(boolean rd) {
        byte val = buffer.get(2);
        if (rd) {
            buffer.put(2, (byte) (val | 0x01));
        } else {
            buffer.put(2, (byte) (val & 0xFE));
        }
    }

    public boolean getRA() {
        return (buffer.get(3) & 0x80) != 0;
    }

    public void setRA(boolean ra) {
        byte val = buffer.get(3);
        if (ra) {
            buffer.put(3, (byte) (val | 0x80));
        } else {
            buffer.put(3, (byte) (val & 0x7F));
        }
    }

    public int getRcode() {
        return buffer.get(3) & 0x0F;
    }

    public void setRcode(int rcode) {
        byte val = buffer.get(3);
        buffer.put(3, (byte) ((val & 0xF0) | rcode));
    }

    public int getQDCount() {
        return buffer.getShort(4) & 0xFFFF;
    }

    public void setQDCount(int count) {
        buffer.putShort(4, (short) count);
    }

    public int getANCount() {
        return buffer.getShort(6) & 0xFFFF;
    }

    public void setANCount(int count) {
        buffer.putShort(6, (short) count);
    }

    public int getNSCount() {
        return buffer.getShort(8) & 0xFFFF;
    }

    public void setNSCount(int count) {
        buffer.putShort(8, (short) count);
    }

    public int getARCount() {
        return buffer.getShort(10) & 0xFFFF;
    }

    public void setARCount(int count) {
        buffer.putShort(10, (short) count);
    }

    /**
     * Return the name at the current position() of the buffer.
     *
     * The encoding of names in DNS messages is a bit tricky.
     * You should read section 4.1.4 of RFC 1035 very, very carefully.  Then you should draw a picture of
     * how some domain names might be encoded.  Once you have the data structure firmly in your mind, then
     * design the code to read names.
     *
     * @return The decoded name
     */
    public String getName() {
        // TODO: Complete this method
        int pos = buffer.position();
        StringBuilder name = new StringBuilder();
        int stringLength = buffer.get();

        int goBack; // position of the current ptr (if it encounters ptr)
        int returnPos = 0; // position of ptr that the buffer should return to after running through all references to ptrs

        if ((stringLength & 0xC0) == 0xC0) { // checking if pointer
            goBack = buffer.position() - 1; // saving position of the current ptr to go back to
            returnPos = goBack; // saving the position it should return to
            int offset = (buffer.getShort(pos) & 0x3FFF); // getting the offset of pointer
            buffer.position(offset); // moving to offset
            stringLength = buffer.get(); // getting the length of string in that offset
        }

        if (stringLength == 0) {
            return "";
        }

        while (stringLength != 0) {

            for (int i = 0; i < stringLength; i++) {
                byte character = buffer.get(); // getting the byte in this position
                name.append((char) character); // putting the char equivalent of the byte to name
            }
            stringLength = buffer.get(); // checking the next string's length
            if (stringLength != 0) { // if there is no next string, jumps out of loop
                name.append("."); // if there is next string, adds "." to the name
                if ((stringLength & 0xC0) == 0xC0) { // checks if this next string is a pointer
                    returnPos = Math.max(returnPos, buffer.position() - 1); // sets the return position to whatever the larger position is
                    goBack = buffer.position() - 1; //saves the go back position to where the pointer position is (since right now ptr is at the position of offset)
                    buffer.position(goBack); // moves position back to where pointer is
                    name.append(getName()); // with the current buffer position at a pointer, it will get the pointer offset and string in the offset through recursion
                    buffer.position(returnPos + 2); // once the ptr's string is added to name, we move position to after the pointer's offset's position (which is where RecordType is)
                    break; // breaks from loop
                }
            }
        }
        if (returnPos != 0) { // if return position has been changed, then it means the position it should return to is returnPos+2
            buffer.position(returnPos + 2); // buffer needs to move to where RecordType is, so we do +2
        }

        return name.toString();
    }

    /**
     * The standard toString method that displays everything in a message.
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer, so we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not change
        // the position in the buffer.  We remember what it was and put it back when we are done.
        int end = buffer.position();
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR() ? "Response" : "Query").append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        }
        finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we looking at)
     * @param nrrs Number of resource records
     * @param sb Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n");
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Decode and return the question that appears next in the message.  The current position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {
        // TODO: Complete this method
        String name = getName(); // grabs the host name
        RecordType recordType = RecordType.getByCode(buffer.getShort() & 0xFFFF); // grabs the record type of the name
        RecordClass recordClass = RecordClass.getByCode(buffer.getShort() & 0xFFFF); // grabs the record class of the name

        return new DNSQuestion(name, recordType, recordClass); // returns a question with the name, record type/class gotten above
    }

    /**
     * Decode and return the resource record that appears next in the message.  The current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {
        // TODO: Complete this method
        String name = getName(); // getting name from buffer
        RecordType recordType = RecordType.getByCode(buffer.getShort() & 0xFFFF); // getting the current recordType
        RecordClass recordClass = RecordClass.getByCode(buffer.getShort() & 0xFFFF); // getting the current record class
        DNSQuestion question = new DNSQuestion(name, recordType, recordClass); // making new question with name, recordtype and recordclass

        int ttl = buffer.getInt(); // getting the ttl
        int len  = buffer.getShort() & 0xFFFF; // getting the length of rdlength

        ResourceRecord resourceRecord = new ResourceRecord(question, ttl, name); // makes a new rr with the items found above (just a dummy rr as it will be overwritten)

        if (recordType.equals(RecordType.A) || recordType.equals(RecordType.AAAA)) { // checks what the record type is
            try { // if record type is A or AAAA (which need to read an IP address,
                byte[] bytes = new byte[len]; // we get the length of that ip address and make a new byte array
                buffer.get(bytes); // with that byte array, we grab the bytes in the current position up to rdlength
                resourceRecord = new ResourceRecord(question, ttl, InetAddress.getByAddress(bytes)); // we store this byte array as the type InetAddress into the new rr
            } catch (UnknownHostException e) { // catches exception thrown by getByAddress
                e.printStackTrace();
            }
        } else if (recordType.equals(RecordType.NS) || recordType.equals(RecordType.CNAME) || (recordType.equals(RecordType.MX))) { // else, if record type is NS, CNAME or MX
            if (recordType.equals(RecordType.MX))  { // and if it is MX
                buffer.getShort(); // move up by two bytes for the preference
            }
            name = getName(); // gets the question's name for the exchange and moves position to the end of the rr
            resourceRecord = new ResourceRecord(question, ttl, name); // creates new rr with the name of the question as its string representation
        } else { // else if its SOA or OTHER
            byte[] bytes = new byte[len];
            buffer.get(bytes); // gets an array of bytes from current position
            String str = byteArrayToHexString(bytes); // converts the array of bytes to hex string
            resourceRecord = new ResourceRecord(question, ttl, str); // creates new rr with the hex string as its string representation
        }

        return resourceRecord;
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    public static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }
    /**
     * Helper function that returns a byte array from a hex string representation. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param hexString a string containing the hex value of every byte in the data.
     * @return data a byte array containing the record data.
     */
    public static byte[] hexStringToByteArray(String hexString) {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            String s = hexString.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte)Integer.parseInt(s, 16);
        }
        return bytes;
    }

    /**
     * Add an encoded name to the message. It is added at the current position and uses compression
     * as much as possible.  Make sure you understand the compressed data format of DNS names.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        // TODO: Complete this method
//        String[] array = name.split("\\.");
        List<String> list = new ArrayList<String>(Arrays.asList(name.split("\\."))); // splits the name by "." and puts it into a list

        while (list.size() != 0) { //loops while the list is not empty
            name = String.join("\\.", list); // joins the current state of the list into name
            if (strPosition.get(name) == null) { // checks if the name has already been added to a map
                strPosition.put(name, buffer.position()); // if not, it adds the name into the map with its position
                String s = list.get(0); // grabs the first item in the list which is some string
                buffer.put((byte) s.length()); // puts the length of the string into buffer
                for (int i = 0; i < s.length(); i++) { // loops through the character of the string
                    char character = s.charAt(i); // grabs the char in that index
                    buffer.put((byte) character); // put that char as a byte into buffer
                }
                list.remove(0); // once the string has been put into buffer as bytes, it removes that string from list
            } else {
                buffer.putShort((short) (strPosition.get(name) | 0xC000)); // if the name was already added to the map, then we get the position of the name and change the first two bytes to 11 and put into buffer
                return; // jumps out of loop
            }
        }
        buffer.put((byte) 0); // places a 0 byte as the end of the name added to buffer to show that its the end of name
    }

    /**
     * Add an encoded question to the message at the current position.
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {
        // TODO: Complete this method
        addName(question.getHostName()); // adds host name to buffer
        addQType(question.getRecordType()); // adds record type to buffer
        addQClass(question.getRecordClass()); // adds record class to buffer
        setQDCount(getQDCount() + 1); // increments the QD count by 1
    }

    /**
     * Add an encoded resource record to the message at the current position.
     * The record is added to the additional records section.
     * @param rr The resource record to be added
     */
    public void addResourceRecord(ResourceRecord rr) {
        addResourceRecord(rr, "additional");
    }

    /**
     * Add an encoded resource record to the message at the current position.
     *
     * @param rr The resource record to be added
     * @param section Indicates the section to which the resource record is added.
     *                It is one of "answer", "nameserver", or "additional".
     */
    public void addResourceRecord(ResourceRecord rr, String section) {
        // TODO: Complete this method
        addName(rr.getHostName()); // adds host name to buffer
        addQType(rr.getRecordType()); // adds record type to buffer
        addQClass(rr.getRecordClass()); // adds record class to buffer
        buffer.putInt((int) rr.getRemainingTTL()); // adds TTL to buffer

        RecordType recordType = rr.getRecordType(); // grabs the record type
        if (recordType.equals(RecordType.A) || recordType.equals(RecordType.AAAA)) { // checks if the record type is A or AAAA
            InetAddress inetResult = rr.getInetResult(); // gets the ip address
            buffer.putShort((short) inetResult.getAddress().length); // stored the ip address length to buffer
            buffer.put(inetResult.getAddress()); // then stores the ip address to buffer
        } else if (recordType.equals(RecordType.NS) || recordType.equals(RecordType.CNAME) || recordType.equals(RecordType.MX)) {
            buffer.putShort((short) rr.getTextResult().length()); // stores the length of the name that will be added
            if (recordType.equals(RecordType.MX)) { // and if record type is MX
                buffer.getShort(); // it moves the buffer up by 2 bytes (for preference)
            }
            addName(rr.getTextResult()); // adds name to buffer
        } else { // if record type is SOA or Other
            String text = rr.getTextResult(); // grabs the hex string
            byte[] bytes = hexStringToByteArray(text); // converts that hex string into a byte array
            buffer.putShort((short) bytes.length); // stores the length of byte array into buffer
            buffer.put(bytes); // stores the byte array into buffer
        }

        // increments the appropriate count depending on what section
        if (section.equals("additional")) {
            setARCount(getARCount() + 1);
        } else if (section.equals("nameserver")) {
            setNSCount(getNSCount() + 1);
        } else { // if section = "answer"
            setANCount(getANCount() + 1);
        }

    }




    /**
     * Add an encoded type to the message at the current position.
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {
        // TODO: Complete this method
        buffer.putShort((short) (recordType.getCode()));

    }

    /**
     * Add an encoded class to the message at the current position.
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        // TODO: Complete this method
        buffer.putShort((short) recordClass.getCode());

    }

    /**
     * Return a byte array that contains all the data comprising this message.  The length of the
     * array will be exactly the same as the current position in the buffer.
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {
        // TODO: Complete this method
        int i = buffer.position(); // gets the current buffer position
        byte[] array = new byte[i]; // makes new byte array of length of the buffer position
        buffer.position(0); // puts the buffer position back to 0
        buffer.get(array, 0, i); // gets the populated buffer into array
        return array;

//        return new byte[0];
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[]{
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }
}