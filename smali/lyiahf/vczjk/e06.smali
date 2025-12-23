.class public final Llyiahf/vczjk/e06;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $$this$callbackFlow:Llyiahf/vczjk/s77;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/s77;"
        }
    .end annotation
.end field

.field final synthetic $timeoutJob:Llyiahf/vczjk/v74;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/r09;Llyiahf/vczjk/s77;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e06;->$timeoutJob:Llyiahf/vczjk/v74;

    iput-object p2, p0, Llyiahf/vczjk/e06;->$$this$callbackFlow:Llyiahf/vczjk/s77;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/al1;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/e06;->$timeoutJob:Llyiahf/vczjk/v74;

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    iget-object v0, p0, Llyiahf/vczjk/e06;->$$this$callbackFlow:Llyiahf/vczjk/s77;

    check-cast v0, Llyiahf/vczjk/r77;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r77;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
