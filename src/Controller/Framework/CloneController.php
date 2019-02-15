<?php

namespace App\Controller\Framework;

use App\Command\CommandDispatcherTrait;
use App\Command\Framework\CloneFrameworkCommand;
use App\Command\Framework\CopyFrameworkCommand;
use App\Entity\Framework\LsDoc;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Copy controller.
 *
 * @Route("/clone")
 */
class CloneController extends AbstractController
{
    use CommandDispatcherTrait;

    /**
     * @Route("/framework/{id}", name="clone_framework", methods={"GET"})
     * @Security("is_granted('edit', lsDoc)")
     */
    public function frameworkAction(Request $request, LsDoc $lsDoc): Response
    {
        $command = new CloneFrameworkCommand($lsDoc);
        $this->sendCommand($command);

        return $this->redirectToRoute('doc_tree_view', ['slug' => $lsDoc->getId()]);
    }
}
