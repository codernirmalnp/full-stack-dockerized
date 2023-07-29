import '../styles/main.scss'
import type { AppProps } from 'next/app'

export default function App({ Component, pageProps }: AppProps) {
  return   <div className='dark:bg-darkBlue dark:text-white font-opensans'><Component {...pageProps} /></div>
}
