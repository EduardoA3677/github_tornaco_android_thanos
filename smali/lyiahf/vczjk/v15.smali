.class public final Llyiahf/vczjk/v15;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_await$inlined:Llyiahf/vczjk/t15;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t15;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v15;->$this_await$inlined:Llyiahf/vczjk/t15;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/v15;->$this_await$inlined:Llyiahf/vczjk/t15;

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Ljava/util/concurrent/Future;->cancel(Z)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
