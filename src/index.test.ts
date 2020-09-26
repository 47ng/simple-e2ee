import {
  encrypt,
  decrypt,
  PAYLOAD_REGEX_V1,
  applyKeyToURL,
  getKeyFromURL
} from './index'

test('encrypt generates a key and a payload', () => {
  expect(encrypt('').payload).toMatch(PAYLOAD_REGEX_V1)
  expect(encrypt({}).payload).toMatch(PAYLOAD_REGEX_V1)
  expect(encrypt([]).payload).toMatch(PAYLOAD_REGEX_V1)
  expect(encrypt(null).payload).toMatch(PAYLOAD_REGEX_V1)
  expect(encrypt(42).payload).toMatch(PAYLOAD_REGEX_V1)
  expect(encrypt({ hello: 'world' }).payload).toMatch(PAYLOAD_REGEX_V1)
})

test('Encrypt => Decrypt', () => {
  function testEncryptionDecryption<T>(input: T) {
    const { payload, key } = encrypt(input)
    expect(decrypt(payload, key)).toEqual(input)
  }

  testEncryptionDecryption('')
  testEncryptionDecryption({})
  testEncryptionDecryption([])
  testEncryptionDecryption(null)
  testEncryptionDecryption(42)
  testEncryptionDecryption({ hello: 'world' })
})

test('Failure - Invalid payload', () => {
  const run = () => decrypt('not a payload', 'not a key')
  expect(run).toThrowError('Invalid payload format')
})

test('Failure - Invalid key', () => {
  const run = () =>
    decrypt(
      '1.G3Yvm4G3X97h2-ky8ORVIlVMBbHNVFd_.cNFG6eisWeBkC-Rer6I4J7kZ',
      'not a key'
    )
  expect(run).toThrowError('bad key size')
})

test('Failure - Wrong key', () => {
  const run = () =>
    decrypt(
      '1.G3Yvm4G3X97h2-ky8ORVIlVMBbHNVFd_.cNFG6eisWeBkC-Rer6I4J7kZ',
      'KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM='
    )
  expect(run).toThrowError('Could not decrypt payload (wrong key)')
})

// --

test('Inject key in current URL', () => {
  const url = applyKeyToURL('KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM=')
  expect(url).toEqual(
    'http://localhost/#KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM='
  )
})

test('Inject key in URL', () => {
  const url = applyKeyToURL(
    'KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM=',
    'https://example.com'
  )
  expect(url).toEqual(
    'https://example.com/#KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM='
  )
})

test('Inject key in URL that already has a hash', () => {
  const run = () =>
    applyKeyToURL(
      'KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM=',
      'https://example.com#already-hashed'
    )
  expect(run).toThrow()
})

test('Get key from URL', () => {
  const key = getKeyFromURL(
    'https://example.com#KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM='
  )
  expect(key).toEqual('KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM=')
})

test('Get key from URL without a hash', () => {
  const run = () => getKeyFromURL()
  expect(run).toThrow('Could not retrieve key: no hash in URL')
})

test('Get key from current URL', () => {
  window.location.hash = 'KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM='
  const key = getKeyFromURL()
  expect(key).toEqual('KatLceVEOM2znzX_FGPKu6Zz1adWkhlq9b2R9WRjUsM=')
  window.location.hash = ''
})
