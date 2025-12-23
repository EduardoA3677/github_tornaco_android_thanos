.class public final Llyiahf/vczjk/hm3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $firstMatchStart:Llyiahf/vczjk/fl7;

.field final synthetic $lastMatchEnd:Llyiahf/vczjk/fl7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fl7;Llyiahf/vczjk/fl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hm3;->$firstMatchStart:Llyiahf/vczjk/fl7;

    iput-object p2, p0, Llyiahf/vczjk/hm3;->$lastMatchEnd:Llyiahf/vczjk/fl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/jd5;

    iget-object v0, p0, Llyiahf/vczjk/hm3;->$firstMatchStart:Llyiahf/vczjk/fl7;

    iget v1, v0, Llyiahf/vczjk/fl7;->element:I

    const/4 v2, -0x1

    if-ne v1, v2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/jd5;->OooO0O0()Llyiahf/vczjk/x14;

    move-result-object v1

    iget v1, v1, Llyiahf/vczjk/v14;->OooOOO0:I

    iput v1, v0, Llyiahf/vczjk/fl7;->element:I

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/hm3;->$lastMatchEnd:Llyiahf/vczjk/fl7;

    invoke-virtual {p1}, Llyiahf/vczjk/jd5;->OooO0O0()Llyiahf/vczjk/x14;

    move-result-object p1

    iget p1, p1, Llyiahf/vczjk/v14;->OooOOO:I

    add-int/lit8 p1, p1, 0x1

    iput p1, v0, Llyiahf/vczjk/fl7;->element:I

    const-string p1, ""

    return-object p1
.end method
