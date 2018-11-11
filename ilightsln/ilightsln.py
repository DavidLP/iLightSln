from __future__ import print_function
import binascii
import logging
import asyncio

logger = logging.getLogger('ilightsln')


class Light(object):
    # Std. light settings during init
    __STD_BRIGHTNESS = 100
    __STD_COLOR_TEMP = 100
    __STD_ON = False

    def __init__(self, name, address, gateway):
        logger.debug('New light %s at adress %s', name, str(hex(address)))
        self.name = name
        self.address = address
        # States cannot be queried, set std. assumed states here
        self.on = self.__STD_ON
        self.brightness = self.__STD_BRIGHTNESS
        self.color_temp = self.__STD_COLOR_TEMP
        self._gateway = gateway

    def turn_on(self):
        # Brightness != 0 means light on
        if self._gateway._send_light_command(self.address,
                                             brightness=self.brightness,
                                             color_temp=self.color_temp):
            self.on = True

    async def async_turn_on(self):
        '''  Non blocking async light turn on function'''
        async def ack_callback(data):
            logger.debug('Got acknowledge %s', binascii.hexlify(data))
            self.on = True
        # Brightness != 0 means light on
        logger.debug('Async turn on light %s', self.name)
        await self._gateway._async_send_light_command(self.address,
                                                      brightness=self.brightness,
                                                      color_temp=self.color_temp,
                                                      ack_callback=ack_callback)

    def turn_off(self):
        # Brightness = 0 means turn off
        if self._gateway._send_light_command(self.address,
                                             brightness=0,
                                             color_temp=self.color_temp):
            self.on = False

    async def async_turn_off(self):
        '''  Non blocking async light turn off function'''
        async def ack_callback(data):
            logger.debug('Got acknowledge %s', binascii.hexlify(data))
            self.on = False
        # Brightness = 0 means turn off
        logger.debug('Async turn off light %s', self.name)
        await self._gateway._async_send_light_command(self.address,
                                                      brightness=0,
                                                      color_temp=self.color_temp,
                                                      ack_callback=ack_callback)

    def is_on(self):
        return self.on

    def set_brightness(self, brightness):
        ''' Set brightness setting of light

            Works also if light is off.
        '''

        if brightness < 1:
            self.brightness = 1

        if brightness > 100:
            self.brightness = 100

        if self.is_on():
            if self._intf._send_light_command(self.address,
                                              brightness=brightness,
                                              color_temp=self.color_temp):
                self.brightness = brightness
        else:
            self.brightness = brightness

    async def async_set_brightness(self, brightness):
        ''' Non blocking async set brightness function

            Works also if light is off
        '''

        if brightness < 1:
            brightness = 1

        if brightness > 100:
            brightness = 100

        if self.is_on():
            async def ack_callback(data):  # only change brightness state on success
                logger.debug('Got acknowledge %s', binascii.hexlify(data))
                self.brightness = brightness
            self._gateway._async_send_light_command(self.address,
                                                    brightness=brightness,
                                                    color_temp=self.color_temp)
        else:
            self.brightness = brightness

    def set_color_temp(self, color_temp):
        ''' Set color temperature of light

            Works also if light is off
        '''

        if color_temp < 0:
            color_temp = 0

        if color_temp > 100:
            color_temp = 100

        if self.is_on():
            if self._intf._send_light_command(self.address,
                                              brightness=self.brightness,
                                              color_temp=color_temp):
                self.color_temp = color_temp
        else:
            self.color_temp = color_temp

    async def async_color_temp(self, color_temp):
        ''' Non blocking async color temperature of light function

            Works also if light is off
        '''

        if color_temp < 0:
            color_temp = 0

        if color_temp > 100:
            color_temp = 100

        if self.is_on():
            async def ack_callback(data):  # only change brightness state on success
                logger.debug('Got acknowledge %s', binascii.hexlify(data))
                self.color_temp = color_temp
            self._gateway._async_send_light_command(self.address,
                                                    brightness=self.brightness,
                                                    color_temp=color_temp)
        else:
            self.color_temp = color_temp


class UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.queue = asyncio.Queue()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        remote_addr = self.transport.get_extra_info('peername')
        if remote_addr == addr:  # not sure if this filter is needed for UDP
            self.queue.put_nowait(data)


class ILightSln(object):
    ''' Access the lights managed by a ILightSln zigbee gateway via network.

        A compatible ILightSln gateway should shows a Wifi SSID during setup containing "iLightsln"
        Many rebranded gateways are on the marked (e.g. from Renkforce and smart-mit-led).
        A compatible gateway will likely tell you to install one of the following Android/iOS apps:
            - iLightsln
            - iSmartBulb
            - iHookUp
            - WiFi ER
            - iWiFis
            - Parify Smartlight 

        The UDP protocol to communicate with the device was reverse engineered.
        No special session messages needed. All commands with correct CRC are accepted and return data.

        Light commands (header 0x04):
        UDP payload: HH DDDD NN 11 BB CC 0000 CRC
            HH Likely data header identifying the data type. HH = 0x04 means light commands
            DDDD is the 2 byte device adress as shown in the app. If set to 0x0000 all devices
                are addressed (broadcast)
            NN is a sequence number that is counted up between 0..3 and does not have to be correct
            BB is the brightness 0..64
            CC is the color temperature 0..64; 0 is warm white, 64 is cold white
            CRC 2 byte checksum calculated as the sum of the other bytes & 0xFF

            Constants might have a special meaning and not be constant, function not identified yet.
            Likely light modes (candle, blink, ...) encoded in these.

            Light commands are acknowledged by the gateway by echoing the same message 0x08 header
            instead of 0x04.

        Config commands (header 0x01):
        UDP payload: HH DDDD CRC
            HH Likely data header identifying the data type. HH = 0x01 means config commands
            DDDD unidentified payload. Maybe constant (DDDD=0x7d017a00) for all gateways. 
            CRC 2 byte checksum calculated as the sum of the other bytes & 0xFF

    '''

    _SND_CFG_HEADER = 0x01  # likely header for sending config commands
    _SND_HEADER = 0x04  # likely header for sending light commands
    _RCV_CFG_HEADER = 0x06  # likely header for received configuration data
    _RCV_HEADER = 0x08  # likely header for received light commands ack

    _CONST_1 = 0x11
    _CONST_2 = 0x00
    _CONST_3 = 0x00

    _ACK_WAIT = 0.3  # time to wait for reply from bridge after command send

    def __init__(self, host, port=50000, loop=None):
        self.host = host
        self.port = port
        self.loop = loop

        if not self.loop:
            self.loop = asyncio.get_event_loop()
        task = asyncio.Task(self.loop.create_datagram_endpoint(
            UdpProtocol, remote_addr=(self.host, self.port)))
        self.intf, self.endpoint = self.loop.run_until_complete(task)

        self.lights = []  # light objects
        self._send_cmd_queue = asyncio.Queue()
        asyncio.ensure_future(self._async_send_from_queue())
        # Values in DEZ
        self.seq_num = 0

    def add_lights_from_gateway(self):
        ''' Add the lights that are stored on the gateway '''
        logger.debug('Add lights from gateway')
        cmd = '017d017a00'  # get cfg from gateway cmd
        ret = self._send_command(bytearray.fromhex(cmd))
        if not ret:
            logger.error('Light initialization failed')
            return
        self.n_dev = int(''.join('{:02x}'.format(x) for x in ret[7:8]), 16)
        for d in range(self.n_dev):
            byte_offset = 8 + d * 36
            address = int(''.join('{:02x}'.format(x)
                                  for x in ret[byte_offset:byte_offset + 2]), 16)
            name = ret[byte_offset + 6:byte_offset +
                       23].decode("utf-8").rstrip(' \t\r\n\0')
            self.add_light(name, address)
        logger.info('Initialized %d light(s)', self.n_dev)

    async def async_add_lights_from_gateway(self):
        ''' Non blocking async add the lights that are stored on the gateway '''
        logger.debug('Async add lights from gateway')

        async def parse_reply(data):
            if not data:
                logger.error('Light initialization failed')
                return
            self.n_dev = int(''.join('{:02x}'.format(x)
                                     for x in data[7:8]), 16)
            for d in range(self.n_dev):
                byte_offset = 8 + d * 36
                address = int(''.join('{:02x}'.format(x)
                                      for x in data[byte_offset:byte_offset + 2]), 16)
                name = data[byte_offset + 6:byte_offset +
                            23].decode("utf-8").rstrip(' \t\r\n\0')
                self.add_light(name, address)
            logger.info('Initialized %d light(s)', self.n_dev)

        cmd = '017d017a00'  # get cfg from gateway cmd
        await self._async_send_command(bytearray.fromhex(cmd), parse_reply)

    def add_light(self, name, address):
        ''' Add a new light '''
        try:
            if self[name].address != address:
                logger.error(
                    'Cannot add another light with same name: %s', name)
            else:
                logger.info(
                    'Light with name: %s already added. Skipping.', name)
        except KeyError:
            existing_addresses = [l.address for l in self.lights]
            if address in existing_addresses:
                logger.error(
                    'Cannot add another light with already used adress: %s', hex(address))
            else:
                self.lights.append(Light(name, address, gateway=self))

    def __getitem__(self, name):
        ''' Get light by name '''
        for light in self.lights:
            if light.name == name:
                return light
        else:
            raise KeyError('No light with the name %s', name)

    def _roll_sequence(self):
        self.seq_num += 1
        if self.seq_num > 255:
            self.seq_num = 0

    def _calculate_check_sum(self, data):
        """ Calculate data checksum
            Note: Checksum is equal to SUM(all command bytes) & 0xFF
            Keyword arguments:
              data: bytearray
        """
        check_sum = 0
        for byte_data in data:
            check_sum += byte_data

        return check_sum & 0xFF

    def _send_light_command(self, dev_addr, brightness, color_temp):
        data = [self._SND_HEADER, (dev_addr & 0xFF00) >> 8, dev_addr & 0x00FF,
                self.seq_num, self._CONST_1, brightness, color_temp, self._CONST_2, self._CONST_3]
        return self._send_command(data)

    async def _async_send_light_command(self, dev_addr, brightness, color_temp, ack_callback=None):
        data = [self._SND_HEADER, (dev_addr & 0xFF00) >> 8, dev_addr & 0x00FF,
                self.seq_num, self._CONST_1, brightness, color_temp, self._CONST_2, self._CONST_3]
        await self._async_send_command(data, ack_callback)

    def _send_command(self, cmd):
        ''' Blocking send command

            Returns gateway reply if reply is a correct acknowledge
            and happens within given timeout otherwise returns None
        '''
        data = bytearray(cmd)
        crc = bytearray([self._calculate_check_sum(data)])
        payload = data + crc
        self.intf.sendto(payload)
        logger.debug('Send %s', binascii.hexlify(payload))
        self._roll_sequence()  # not really needed
        try:
            ret = self.loop.run_until_complete(asyncio.wait_for(self.endpoint.queue.get(),
                                                                self._ACK_WAIT, loop=self.loop))
            if bytearray(ret).startswith(self._calc_acknowledge(payload)):
                return ret
        except asyncio.TimeoutError:
            logger.error('Payload %s not answered by bridge',
                         binascii.hexlify(payload))

    def _calc_acknowledge(self, payload):
        ''' Calculate expected return value from gateway '''
        header = payload[:1]
        if header == bytearray([self._SND_HEADER]):  # light command
            ack = payload.copy()
            ack[:1] = bytearray([self._RCV_HEADER])
            ack[-1:] = bytearray([self._calculate_check_sum(ack[:-1])])
            return ack
        elif header == bytearray([self._SND_CFG_HEADER]):  # cfg command
            # only returen header is not a function of the cfgdata itself
            return bytearray([self._RCV_CFG_HEADER])

    async def _async_send_command(self, cmd, ack_callback):
        ''' Non blocking send command

            Acknowledge callback is called when command is correctly
            replied by gateway within given timeout
        '''
        await self._send_cmd_queue.put((cmd, ack_callback))

    async def _async_send_from_queue(self):
        """ Send messages to the gateway as they become available. """
        while True:
            cmd, callback = await self._send_cmd_queue.get()
            data = bytearray(cmd)
            crc = bytearray([self._calculate_check_sum(data)])
            payload = data + crc
            self.intf.sendto(payload)
            logger.debug('Async send %s', binascii.hexlify(payload))
            self._roll_sequence()  # not really needed
            try:
                ret = await asyncio.wait_for(self.endpoint.queue.get(), self._ACK_WAIT, loop=self.loop)
                # callback for correct gateway reply
                if callback and bytearray(ret).startswith(self._calc_acknowledge(payload)):
                    await callback(ret)
            except asyncio.TimeoutError:
                logger.error('Payload %s not answered by bridge',
                             binascii.hexlify(payload))


if __name__ == '__main__':
    logging.basicConfig()
    logger.setLevel(logging.DEBUG)
    loop = asyncio.get_event_loop()
    lights = ILightSln(host='192.168.1.121', loop=loop)
    asyncio.ensure_future(lights.async_add_lights_from_gateway())
    loop.run_forever()
