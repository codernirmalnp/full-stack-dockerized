import { Children, Fragment } from "react";

type Bread = {
  children: React.ReactElement[] | React.ReactElement

}

const Breadcrumb: React.FC<Bread> = ({ children }) => {
  const childrenArray = Children.toArray(children);



  const childrenWtihSeperator = childrenArray.map((child, index) => {
    if (index !== childrenArray.length - 1) {
      return (
        <Fragment key={index} >
          {child}
          <span> <svg className="w-4 h-4 inline-block mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg></span>
        </Fragment>
      );
    }
    return child
  });

  return (
    <nav className="py-12">
      <ol className="flex items-center space-x-4">{childrenWtihSeperator}</ol>
    </nav>
  );
};

export default Breadcrumb;