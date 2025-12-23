.class public final Llyiahf/vczjk/jk4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_await:Llyiahf/vczjk/wn0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/wn0<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wn0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jk4;->$this_await:Llyiahf/vczjk/wn0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/jk4;->$this_await:Llyiahf/vczjk/wn0;

    invoke-interface {p1}, Llyiahf/vczjk/wn0;->cancel()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
