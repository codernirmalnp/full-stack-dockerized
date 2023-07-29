import React from 'react'
import Image from 'next/image'
export const Project = () => {
  return (
    <section id="creations">
      {/*Creations Container */}
      <div className="container max-w-6xl mx-auto my-32 px-6 text-gray-900 md:px-0">
        {/*Creations Header */}
        <div className="flex justify-center mb-20 md:justify-between">
          <h2 className="text-4xl text-center uppercase md:text-left md:text-5xl">
            Projects
          </h2>

          <button className="hidden btn md:block">See All</button>
        </div>

        {/*Items Container */}
        <div className="item-container">
          {/*Item 1 */}
          <div className="group item">
            {/*Desktop Image */}
            <div className="relative h-96  w-full duration-200 md:block group-hover:scale-110">
              <Image
                fill
                src="/project1.jpg"
                alt=""
                className=""
                style={{ objectFit: "contain" }}
              />

            </div>

            {/*Item Gradient */}
            <div className="item-gradient"></div>
            {/*Item Text */}
            <h5>Kiosk Cloud</h5>
          </div>


        </div>


        <div className="flex justify-center mt-10 md:hidden">
          <button className="btn w-full md:hidden">See All</button>
        </div>
      </div>
    </section>
  )
}
