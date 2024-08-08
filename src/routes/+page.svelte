<script lang="ts">
	import { bases } from 'multiformats/basics';
	import { decode } from 'multiformats/hashes/digest';
	import { toHex, fromHex } from 'multiformats/bytes';
	import { multicodecs } from '$lib/index.js';

	interface DecodedHash {
		multibase: string;
		hashName: string;
		hashCode: string;
		digest: Uint8Array;
		length: number;
	}

	let inputHash: string = '';
	let decodedHash: DecodedHash | null = null;
	let error: string = '';
	$: hasResult = decodedHash || error;

	// type MultibaseFormats = keyof typeof bases;

	function getBase(hash: string): any | null {
		const prefix = hash[0];
		const pair = Object.entries(bases).find(([_k, base]) => base.prefix === prefix);
		return pair ? pair[1] : null;
	}

	function decodeMultibase() {
		decodedHash = null;
		error = '';
		const encodedHash = inputHash.trim();
		if (encodedHash === '') {
			return;
		}
		try {
			error = '';
			let baseName = 'None';
			let multihashEncoded =
				encodedHash.substring(0, 2) === '0x' ? fromHex(encodedHash.substring(2)) : null;
			if (encodedHash.substring(0, 2) !== '0x') {
				const base = getBase(encodedHash);
				if (!base) {
					error = 'Unknown Encoding';
					return;
				}
				multihashEncoded = base.decode(encodedHash) || null;
				baseName = base.name;
			}
			if (!multihashEncoded) {
				throw new Error('Unable to decode');
			}

			const decodedMultihash = decode(multihashEncoded);
			const multicode = `0x${decodedMultihash.code.toString(16)}`;
			const multicodec = multicodecs.find((x) => x.code === multicode);
			decodedHash = {
				multibase: baseName,
				hashName: multicodec ? multicodec.name : 'Unknown',
				hashCode: `0x${decodedMultihash.code.toString()}`,
				digest: decodedMultihash.digest,
				length: decodedMultihash.digest.length
			};
		} catch (err: unknown) {
			error = (err as Error).message || 'Unable to decode';
		}
	}
</script>

<main>
	<h1>Multiformat Multibase Multihash Inspector</h1>

	<label for="input-hash">Enter a Multibase hash or a 0x prefixed hex Multihash:</label>
	<input type="text" id="input-hash" bind:value={inputHash} />
	<button on:click={decodeMultibase}>Decode</button>

	{#if hasResult}
		<div>
			<h2>Decoded Multihash</h2>
			{#if decodedHash}
				<p>Multibase Encoding: {decodedHash.multibase}</p>
				<p>Hash Algorithm: {decodedHash.hashName} ({decodedHash.hashCode})</p>
				<p>Digest: {decodedHash ? '0x' + toHex(decodedHash.digest) : 'Unknown'}</p>
				<p>Length: {decodedHash.length}</p>
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
