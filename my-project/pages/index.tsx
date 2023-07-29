import Head from 'next/head'
import Header from '../components/header/Header'
import Hero from '../components/hero/Hero'
import { Experience } from '../components/experience/experiance'
import { Blog } from '../components/blog/blog'
import { Testimonials } from '../components/testomonial/testomonial'
import { Project } from '../components/project/project'
import { Footer } from '../components/footer/Footer'

export default function Index() {
  return (

    <>
    



      <Header />
      <Hero />
      <Experience/>
      <Blog/>
      <Testimonials/>
      <Project/>
      <Footer/>

  
     
           

          
       

    

     






    </>

  )
}
