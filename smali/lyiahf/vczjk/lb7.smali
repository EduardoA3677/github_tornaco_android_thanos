.class public final Llyiahf/vczjk/lb7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:Ljava/lang/Object;

.field public final OooO00o:Llyiahf/vczjk/eb4;

.field public final OooO0O0:Llyiahf/vczjk/v72;

.field public final OooO0OO:Llyiahf/vczjk/u66;

.field public final OooO0Oo:[Ljava/lang/Object;

.field public OooO0o:I

.field public OooO0o0:I

.field public final OooO0oO:Ljava/util/BitSet;

.field public OooO0oo:Llyiahf/vczjk/o0O00o00;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;ILlyiahf/vczjk/u66;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lb7;->OooO00o:Llyiahf/vczjk/eb4;

    iput-object p2, p0, Llyiahf/vczjk/lb7;->OooO0O0:Llyiahf/vczjk/v72;

    iput p3, p0, Llyiahf/vczjk/lb7;->OooO0o0:I

    iput-object p4, p0, Llyiahf/vczjk/lb7;->OooO0OO:Llyiahf/vczjk/u66;

    new-array p1, p3, [Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/lb7;->OooO0Oo:[Ljava/lang/Object;

    const/16 p1, 0x20

    if-ge p3, p1, :cond_0

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/lb7;->OooO0oO:Ljava/util/BitSet;

    return-void

    :cond_0
    new-instance p1, Ljava/util/BitSet;

    invoke-direct {p1}, Ljava/util/BitSet;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lb7;->OooO0oO:Ljava/util/BitSet;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ph8;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->OooOOO()Ljava/lang/Object;

    move-result-object v0

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/lb7;->OooO0O0:Llyiahf/vczjk/v72;

    if-nez v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/lh1;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_3

    sget-object v0, Llyiahf/vczjk/w72;->OooOo:Llyiahf/vczjk/w72;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-nez v0, :cond_2

    :try_start_0
    iget-object v0, p1, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v0, v2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/e94;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Llyiahf/vczjk/na4; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception v0

    invoke-interface {p1}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object p1

    new-instance v2, Llyiahf/vczjk/ma4;

    invoke-direct {v2, v1, p1}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/na4;->OooO0o(Llyiahf/vczjk/ma4;)V

    :cond_1
    throw v0

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->OooOOO0()I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    filled-new-array {v0, v3}, [Ljava/lang/Object;

    move-result-object v0

    const-string v3, "Missing creator property \'%s\' (index %d); `DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES` enabled"

    invoke-virtual {v2, p1, v3, v0}, Llyiahf/vczjk/v72;->o0000O(Llyiahf/vczjk/db0;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v1

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->OooOOO0()I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    filled-new-array {v0, v3}, [Ljava/lang/Object;

    move-result-object v0

    const-string v3, "Missing required creator property \'%s\' (index %d)"

    invoke-virtual {v2, p1, v3, v0}, Llyiahf/vczjk/v72;->o0000O(Llyiahf/vczjk/db0;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v1

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->OooOOO()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v2, p1}, Llyiahf/vczjk/v72;->ooOO(Ljava/lang/Object;)V

    throw v1
.end method

.method public final OooO0O0(Llyiahf/vczjk/ph8;Ljava/lang/Object;)Z
    .locals 3

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->OooOOO0()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/lb7;->OooO0Oo:[Ljava/lang/Object;

    aput-object p2, v0, p1

    iget-object p2, p0, Llyiahf/vczjk/lb7;->OooO0oO:Ljava/util/BitSet;

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-nez p2, :cond_2

    iget p2, p0, Llyiahf/vczjk/lb7;->OooO0o:I

    shl-int p1, v1, p1

    or-int/2addr p1, p2

    if-eq p2, p1, :cond_3

    iput p1, p0, Llyiahf/vczjk/lb7;->OooO0o:I

    iget p1, p0, Llyiahf/vczjk/lb7;->OooO0o0:I

    sub-int/2addr p1, v1

    iput p1, p0, Llyiahf/vczjk/lb7;->OooO0o0:I

    if-gtz p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/lb7;->OooO0OO:Llyiahf/vczjk/u66;

    if-eqz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/lb7;->OooO:Ljava/lang/Object;

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    return v0

    :cond_1
    :goto_0
    return v1

    :cond_2
    invoke-virtual {p2, p1}, Ljava/util/BitSet;->get(I)Z

    move-result v2

    if-nez v2, :cond_3

    invoke-virtual {p2, p1}, Ljava/util/BitSet;->set(I)V

    iget p1, p0, Llyiahf/vczjk/lb7;->OooO0o0:I

    sub-int/2addr p1, v1

    iput p1, p0, Llyiahf/vczjk/lb7;->OooO0o0:I

    :cond_3
    return v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/ph8;Ljava/lang/Object;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/kb7;

    iget-object v1, p0, Llyiahf/vczjk/lb7;->OooO0oo:Llyiahf/vczjk/o0O00o00;

    const/4 v2, 0x1

    invoke-direct {v0, v1, p2, p1, v2}, Llyiahf/vczjk/kb7;-><init>(Llyiahf/vczjk/o0O00o00;Ljava/lang/Object;Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/lb7;->OooO0oo:Llyiahf/vczjk/o0O00o00;

    return-void
.end method

.method public final OooO0Oo(Ljava/lang/String;)Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/lb7;->OooO0OO:Llyiahf/vczjk/u66;

    if-eqz v0, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/u66;->propertyName:Llyiahf/vczjk/xa7;

    invoke-virtual {v1}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, v0, Llyiahf/vczjk/u66;->_deserializer:Llyiahf/vczjk/e94;

    iget-object v0, p0, Llyiahf/vczjk/lb7;->OooO00o:Llyiahf/vczjk/eb4;

    iget-object v1, p0, Llyiahf/vczjk/lb7;->OooO0O0:Llyiahf/vczjk/v72;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/lb7;->OooO:Ljava/lang/Object;

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method
