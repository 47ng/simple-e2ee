import nacl from 'tweetnacl'
import b64 from '@47ng/codec/dist/b64'
import utf8 from '@47ng/codec/dist/utf8'
import { URL } from 'url'

export function encrypt<T>(message: T) {
  const key = nacl.randomBytes(nacl.secretbox.keyLength)
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  const payload = utf8.encode(JSON.stringify(message))
  const ciphertext = nacl.secretbox(payload, nonce, key)
  return {
    payload: ['1', b64.encode(nonce), b64.encode(ciphertext)].join('.'),
    key: b64.encode(key)
  }
}

export const PAYLOAD_REGEX_V1 = /^1\.([a-zA-Z0-9-_]{32})\.([a-zA-Z0-9-_]{24,})={0,2}$/

export function decrypt<T>(payload: string, key: string): T {
  const match = payload.match(PAYLOAD_REGEX_V1)
  if (!match) {
    throw new Error('Invalid payload format')
  }
  const nonce = b64.decode(match[1])
  const ciphertext = b64.decode(match[2])
  const message = nacl.secretbox.open(ciphertext, nonce, b64.decode(key))
  if (!message) {
    throw new Error('Could not decrypt payload (wrong key)')
  }
  const json = utf8.decode(message)
  return JSON.parse(json)
}

export function applyKeyToURL(key: string, baseURL?: string) {
  const url = new URL(baseURL ?? window.location.toString())
  if (!!url.hash) {
    throw new Error(
      'URL already has a hash part, this will conflict with the E2EE key'
    )
  }
  url.hash = key
  return url.toString()
}

export function getKeyFromURL(baseURL?: string) {
  const url = baseURL ? new URL(baseURL) : window.location
  const hash = url.hash.replace(/^#/, '')
  if (hash === '') {
    throw new Error('Could not retrieve key: no hash in URL')
  }
  return hash
}
