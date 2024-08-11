<script lang="ts">
	import { bases, varint } from 'multiformats/basics';
	import { decode } from 'multiformats/hashes/digest';
	import { toHex, fromHex } from 'multiformats/bytes';
	import { multicodecs } from '$lib/index.js';

	interface DecodedMultiformat {
		multibase: string;
		multicodec: string;
		multicodecName: string;
		multicodecTag: string;
		ipldCode?: string;
		ipldName?: string;
		hashCode?: string;
		hashName?: string;
		digest?: Uint8Array;
		length?: number;
		bytes?: Uint8Array;
	}

	let inputMultiformat: string = '';
	let decodedMultiformat: DecodedMultiformat | null = null;
	let error: string = '';
	$: hasResult = decodedMultiformat || error;

	// type MultibaseFormats = keyof typeof bases;

	function getBase(multiformat: string): any | null {
		const prefix = multiformat[0];
		const pair = Object.entries(bases).find(([_k, base]) => base.prefix === prefix);
		return pair ? pair[1] : null;
	}

	function decodeInput() {
		decodedMultiformat = null;
		error = '';
		const encodedMultiformat = inputMultiformat.trim();
		if (encodedMultiformat === '') {
			return;
		}
		try {
			error = '';
			let baseName = 'None';
			let multiformatEncoded =
				encodedMultiformat.substring(0, 2) === '0x'
					? fromHex(encodedMultiformat.substring(2))
					: null;
			if (encodedMultiformat.substring(0, 2) !== '0x') {
				const base = getBase(encodedMultiformat);
				if (!base) {
					error = 'Unknown Encoding';
					return;
				}
				multiformatEncoded = base.decode(encodedMultiformat) || null;
				baseName = base.name;
			}
			if (!multiformatEncoded) {
				throw new Error('Unable to decode');
			}
			decodedMultiformat = decodeMultiformat(multiformatEncoded, baseName);
		} catch (err: unknown) {
			error = (err as Error).message || 'Unable to decode';
		}
	}

	function decodeMultiformat(multiformatEncoded: Uint8Array, baseName: string) {
		let decodedMultiformat: DecodedMultiformat | null = null;
		const [code, sizeOffset] = varint.decode(multiformatEncoded);
		const multicode = `0x${code.toString(16).padStart(2, '0')}`;
		const multicodec = multicodecs.find((x) => x.code === multicode);
		decodedMultiformat = {
			multibase: baseName,
			multicodecName: multicodec ? multicodec.name : 'Unknown',
			multicodecCode: multicodec.code,
			multicodecTag: multicodec.tag
		};
		switch (multicodec.tag) {
			case 'multihash':
				const decodedMultihash = decode(multiformatEncoded);
				decodedMultiformat.digest = decodedMultihash.digest;
				decodedMultiformat.length = decodedMultihash.digest.length;
				break;
			case 'cid':
				if (multicodec.name === 'cidv1') {
					const [ipldCode, ipldOffset] = varint.decode(multiformatEncoded.subarray(sizeOffset));
					const ipldHexCode = `0x${ipldCode.toString(16).padStart(2, '0')}`;
					console.log({ ipldCode });
					const ipldMulticodec = multicodecs.find((x) => x.code === ipldHexCode);
					decodedMultiformat.ipldCode = ipldHexCode;
					decodedMultiformat.ipldName = ipldMulticodec.name;

					// Recursively handle the remaining multihash
					const internalDecoded = decodeMultiformat(
						multiformatEncoded.subarray(sizeOffset + ipldOffset),
						baseName
					);
					decodedMultiformat.hashName = internalDecoded.multicodecName;
					decodedMultiformat.hashCode = internalDecoded.multicodecCode;
					decodedMultiformat.digest = internalDecoded.digest;
					decodedMultiformat.length = internalDecoded.digest.length;
					break;
				}
			default:
				decodedMultiformat.bytes = multiformatEncoded.subarray(sizeOffset);
		}
		return decodedMultiformat;
	}
</script>

<main>
	<h1>Multiformat Multibase Inspector (Multihash and More)</h1>

	<label for="input-hash">Enter a Multibase string or a 0x prefixed hex Multiformat value:</label>
	<input type="text" id="input-multiformat" bind:value={inputMultiformat} />
	<button on:click={decodeInput}>Decode</button>

	{#if hasResult}
		<div>
			<h2>Decoded Multiformat</h2>
			{#if decodedMultiformat}
				<p>Multibase Encoding: {decodedMultiformat.multibase}</p>
				<p>
					Multicodec Name: {decodedMultiformat.multicodecName} ({decodedMultiformat.multicodecCode})
				</p>
				<p>Multicodec Tag: {decodedMultiformat.multicodecTag}</p>
				{#if decodedMultiformat.ipldCode}
					<p>IPLD Codec: {decodedMultiformat.ipldName} ({decodedMultiformat.ipldCode})</p>
					<p>CID Hash Algorithm: {decodedMultiformat.hashName} ({decodedMultiformat.hashCode})</p>
				{/if}
				{#if decodedMultiformat.digest}
					<p>Digest: {decodedMultiformat ? '0x' + toHex(decodedMultiformat.digest) : 'Unknown'}</p>
					<p>Length: {decodedMultiformat.length}</p>
				{:else}
					<p>Bytes: {'0x' + toHex(decodedMultiformat.bytes)}</p>
					<p>Length: {decodedMultiformat.bytes.length}</p>
				{/if}
			{:else if error}
				<p>Error: {error}</p>
			{/if}
		</div>
	{/if}
</main>

<style>
	main {
		max-width: 1000px;
		margin: 0 auto;
		padding: 3rem;
	}

	label {
		display: block;
		margin-bottom: 0.5rem;
	}

	input {
		width: 100%;
	}

	input,
	button {
		font-size: 1rem;
		padding: 0.5rem 1rem;
		margin-bottom: 1rem;
		box-sizing: border-box;
	}
</style>
