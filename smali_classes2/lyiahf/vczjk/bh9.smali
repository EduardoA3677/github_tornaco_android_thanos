.class public final Llyiahf/vczjk/bh9;
.super Llyiahf/vczjk/ak1;
.source "SourceFile"


# instance fields
.field public OooO0oO:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/ak1;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bh9;->OooO0oO:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ika;)V
    .locals 0

    invoke-interface {p1, p0}, Llyiahf/vczjk/ika;->OooO0O0(Llyiahf/vczjk/bh9;)V

    return-void
.end method

.method public final OooOO0o()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "literal="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/bh9;->OooO0oO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
