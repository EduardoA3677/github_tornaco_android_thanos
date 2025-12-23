.class public final Llyiahf/vczjk/qy6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/uy6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uy6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qy6;->this$0:Llyiahf/vczjk/uy6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Landroid/view/MotionEvent;

    iget-object v0, p0, Llyiahf/vczjk/qy6;->this$0:Llyiahf/vczjk/uy6;

    iget-object v0, v0, Llyiahf/vczjk/uy6;->OooOOO0:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    const-string p1, "onTouchEvent"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method
