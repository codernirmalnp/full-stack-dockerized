import React from 'react'

export const Topbar = () => {
    const [isOpen, setIsOpen] = React.useState(false);

    const toggleDropdown = () => {
        setIsOpen(!isOpen);
    };
    return (
        <header className="absolute top-0 left-0 w-full grid grid-cols-[1fr,auto]   py-4 px-6 ">
            <div className="flex items-center uppercase">
                <span className="text-xl font-bold">Dashboard</span>
            </div>
            {/* Admin profile */}
            <div className="flex items-center space-x-4 cursor-pointer px-2  py-2">
                <div className='w-12 h-12 rounded-full border-2 border-gray-900 overflow-hidden'>
                    {/* <img src="/profile.svg" alt="" className='w-full h-full object-cover' /> */}

                </div>

                <div className="font-md text-gray-900  flex gap-2" onClick={toggleDropdown}>
                    <div className="cursor-pointer">Nirmal Dangi</div>
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
                    </svg>
                </div>



                {isOpen && (
                    <div className="origin-top-right absolute top-14 right-0 mt-4 z-20 w-48 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5">
                        <div
                            className="py-1"
                            role="menu"
                            aria-orientation="vertical"
                            aria-labelledby="options-menu"
                        >
                            <a
                                href="#"
                                className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                                role="menuitem"
                            >
                                Logout
                            </a>

                        </div>
                    </div>
                )}
            </div>

            {/* Add more admin actions or menu items here */}

        </header >
    )
}
