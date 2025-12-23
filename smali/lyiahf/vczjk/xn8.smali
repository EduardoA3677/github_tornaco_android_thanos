.class public final Llyiahf/vczjk/xn8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $onComplete:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $onUndeliveredElement:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/zn8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zn8;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fz1;Llyiahf/vczjk/zn8;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/ye1;->OooOOo:Llyiahf/vczjk/ye1;

    iput-object p1, p0, Llyiahf/vczjk/xn8;->$onComplete:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/xn8;->this$0:Llyiahf/vczjk/zn8;

    iput-object v0, p0, Llyiahf/vczjk/xn8;->$onUndeliveredElement:Llyiahf/vczjk/ze3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Ljava/lang/Throwable;

    iget-object v0, p0, Llyiahf/vczjk/xn8;->$onComplete:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/xn8;->this$0:Llyiahf/vczjk/zn8;

    iget-object v0, v0, Llyiahf/vczjk/zn8;->OooO0OO:Llyiahf/vczjk/jj0;

    const/4 v1, 0x0

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/jj0;->OooOOO0(Ljava/lang/Throwable;Z)Z

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/xn8;->this$0:Llyiahf/vczjk/zn8;

    iget-object v0, v0, Llyiahf/vczjk/zn8;->OooO0OO:Llyiahf/vczjk/jj0;

    invoke-virtual {v0}, Llyiahf/vczjk/jj0;->OooO0OO()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/jt0;->OooO00o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v0, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/xn8;->$onUndeliveredElement:Llyiahf/vczjk/ze3;

    invoke-interface {v2, v0, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-object v0, v1

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_0

    return-object v1
.end method
