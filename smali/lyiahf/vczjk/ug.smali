.class public final Llyiahf/vczjk/ug;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $callback:Landroid/view/Choreographer$FrameCallback;

.field final synthetic this$0:Llyiahf/vczjk/wg;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wg;Llyiahf/vczjk/vg;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ug;->this$0:Llyiahf/vczjk/wg;

    iput-object p2, p0, Llyiahf/vczjk/ug;->$callback:Landroid/view/Choreographer$FrameCallback;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/ug;->this$0:Llyiahf/vczjk/wg;

    iget-object p1, p1, Llyiahf/vczjk/wg;->OooOOO0:Landroid/view/Choreographer;

    iget-object v0, p0, Llyiahf/vczjk/ug;->$callback:Landroid/view/Choreographer$FrameCallback;

    invoke-virtual {p1, v0}, Landroid/view/Choreographer;->removeFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
