.class public final Llyiahf/vczjk/qa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/xa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qa;->this$0:Llyiahf/vczjk/xa;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/qa;->this$0:Llyiahf/vczjk/xa;

    iget-object v0, v0, Llyiahf/vczjk/xa;->oo0o0Oo:Landroid/view/MotionEvent;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/view/MotionEvent;->getActionMasked()I

    move-result v0

    const/4 v1, 0x7

    if-eq v0, v1, :cond_0

    const/16 v1, 0x9

    if-eq v0, v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/qa;->this$0:Llyiahf/vczjk/xa;

    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    move-result-wide v1

    iput-wide v1, v0, Llyiahf/vczjk/xa;->o0O0O00:J

    iget-object v0, p0, Llyiahf/vczjk/qa;->this$0:Llyiahf/vczjk/xa;

    iget-object v1, v0, Llyiahf/vczjk/xa;->o000000O:Llyiahf/vczjk/ra;

    invoke-virtual {v0, v1}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
