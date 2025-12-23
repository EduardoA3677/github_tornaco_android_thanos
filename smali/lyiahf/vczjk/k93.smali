.class public final Llyiahf/vczjk/k93;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $interaction:Llyiahf/vczjk/j24;

.field final synthetic $this_emitWithFallback:Llyiahf/vczjk/rr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/j24;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/k93;->$this_emitWithFallback:Llyiahf/vczjk/rr5;

    iput-object p2, p0, Llyiahf/vczjk/k93;->$interaction:Llyiahf/vczjk/j24;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/k93;->$this_emitWithFallback:Llyiahf/vczjk/rr5;

    iget-object v0, p0, Llyiahf/vczjk/k93;->$interaction:Llyiahf/vczjk/j24;

    check-cast p1, Llyiahf/vczjk/sr5;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
