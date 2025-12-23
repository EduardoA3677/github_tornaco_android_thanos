.class public final Llyiahf/vczjk/a96;
.super Llyiahf/vczjk/ks7;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ks7;

.field public final OooOOOO:Llyiahf/vczjk/ih7;

.field public OooOOOo:Ljava/io/IOException;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ks7;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/a96;->OooOOO:Llyiahf/vczjk/ks7;

    new-instance v0, Llyiahf/vczjk/xc0;

    invoke-virtual {p1}, Llyiahf/vczjk/ks7;->OooOOOO()Llyiahf/vczjk/nj0;

    move-result-object p1

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/xc0;-><init>(Llyiahf/vczjk/a96;Llyiahf/vczjk/nj0;)V

    invoke-static {v0}, Llyiahf/vczjk/ng0;->OooOOO(Llyiahf/vczjk/rx8;)Llyiahf/vczjk/ih7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/a96;->OooOOOO:Llyiahf/vczjk/ih7;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/a96;->OooOOO:Llyiahf/vczjk/ks7;

    invoke-virtual {v0}, Llyiahf/vczjk/ks7;->OooO0Oo()J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/uf5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a96;->OooOOO:Llyiahf/vczjk/ks7;

    invoke-virtual {v0}, Llyiahf/vczjk/ks7;->OooO0oO()Llyiahf/vczjk/uf5;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOOO()Llyiahf/vczjk/nj0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a96;->OooOOOO:Llyiahf/vczjk/ih7;

    return-object v0
.end method

.method public final close()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a96;->OooOOO:Llyiahf/vczjk/ks7;

    invoke-virtual {v0}, Llyiahf/vczjk/ks7;->close()V

    return-void
.end method
