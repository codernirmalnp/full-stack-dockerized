import React from 'react'
import { CSS3, Git, HTML5, Illustrator, MongoDB, NodeJS, PhotoShop, PostgreSql, Python, ReactJS, TailwindCSS } from '../svg/skill/index'
import Image from 'next/image'

const Hero = () => {
  const logoList: Array<{ logo: React.ReactNode, title: string }> = [{
    logo: <CSS3 />,
    title: "CSS3"
  },
  {
    logo: <Git />,
    title: "Git"
  },
  {
    logo: <HTML5 />,
    title: "html5"
  },
  {
    logo: <Illustrator />,
    title: "Illustrator"
  },
  {
    logo: <MongoDB />,
    title: "Mongo Db"
  },
  {
    logo: <NodeJS />,
    title: "Node JS"
  },
  {
    logo: <PhotoShop />,
    title: "Photoshop"
  },
  {
    logo: <PostgreSql />,
    title: "Postgre Sql"
  },

  {
    logo: <ReactJS />,
    title: "React"
  },
  {
    logo: <TailwindCSS />,
    title: "Tailwind CSS"
  }
  ]
  return (
    <>
      {/* Hero Section*/}
      <section
        id="hero"

      >
        {/* Hero Container*/}
        <div className="container mx-auto px-6  md:pt-20 pb-52">
          {/*Flex Container for image and description*/}
          <div className='flex flex-col w-full md:mt-6 md:flex-row justify-around items-center '>
            {/*Image Container*/}
            <div className="relative max-w-md  md:mx-auto h-96 md:w-1/2 w-96 ">
              <Image src="/profile.svg" alt="" fill style={{ objectFit: "cover" }} className="" />
            </div>

            <div className='md:w-1/2 w-full text-center md:text-left md:mx-auto'>
              <h1
                className=" mb-10 text-3xl font-bold leading-normal mt-14 md:text-4xl"
              >
                Agile Software Developer
              </h1>
              <p className="mb-10 text-sm md:max-w-xl md:text-lg">
                Hi, I am Nirmal Dangi Fullstack web developer who solve your business Problem into online.
              </p>
              <div className=' dark:opacity-80 max-w-sm  rounded-md'>
                <ul className='flex flex-row items-center  md:space-x-7  flex-wrap '>
                  {logoList.map((_value, key) => {
                    return <li key={key}>{_value?.logo}</li>
                  })}

                </ul>
              </div>
              <button className="p-3 rounded-full w-52 mt-10  bg-accentCyan hover:scale-95">
                Download CV
              </button>
            </div>

          </div>



        </div>

      </section>
    </>
  )
}

export default Hero;
