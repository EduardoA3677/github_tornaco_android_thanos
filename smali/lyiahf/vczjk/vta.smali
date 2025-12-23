.class public abstract Llyiahf/vczjk/vta;
.super Llyiahf/vczjk/aw1;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ay8;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/pd2;->OooO00o:Llyiahf/vczjk/od2;

    sget-object v1, Llyiahf/vczjk/tn7;->OooOOOO:Llyiahf/vczjk/tn7;

    invoke-direct {p0, v0, p1, v1}, Llyiahf/vczjk/aw1;-><init>(Llyiahf/vczjk/od2;Llyiahf/vczjk/ay8;Llyiahf/vczjk/tn7;)V

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/od2;)Llyiahf/vczjk/aw1;
    .locals 1

    new-instance p1, Ljava/lang/RuntimeException;

    const-string v0, "unsupported"

    invoke-direct {p1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0O0()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooOO0(I)Llyiahf/vczjk/aw1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/aw1;->OooO0OO:Llyiahf/vczjk/tn7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/tn7;->OooOO0O(I)Llyiahf/vczjk/tn7;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/aw1;->OooOO0O(Llyiahf/vczjk/tn7;)Llyiahf/vczjk/aw1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0o(Llyiahf/vczjk/ol0;)V
    .locals 0

    return-void
.end method
