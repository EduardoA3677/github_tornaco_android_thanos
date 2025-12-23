.class public final Llyiahf/vczjk/hc4;
.super Llyiahf/vczjk/zc4;
.source "SourceFile"


# static fields
.field public static final OooOooO:Llyiahf/vczjk/xv2;

.field public static final OooOooo:Llyiahf/vczjk/hb4;


# instance fields
.field public final OooOoOO:Ljava/util/ArrayList;

.field public OooOoo:Llyiahf/vczjk/g94;

.field public OooOoo0:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/xv2;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/xv2;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/hc4;->OooOooO:Llyiahf/vczjk/xv2;

    new-instance v0, Llyiahf/vczjk/hb4;

    const-string v1, "closed"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hb4;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/hc4;->OooOooo:Llyiahf/vczjk/hb4;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/hc4;->OooOooO:Llyiahf/vczjk/xv2;

    invoke-direct {p0, v0}, Llyiahf/vczjk/zc4;-><init>(Ljava/io/Writer;)V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    sget-object v0, Llyiahf/vczjk/va4;->OooOOO0:Llyiahf/vczjk/va4;

    iput-object v0, p0, Llyiahf/vczjk/hc4;->OooOoo:Llyiahf/vczjk/g94;

    return-void
.end method


# virtual methods
.method public final OooO0oO()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/w84;

    invoke-direct {v0}, Llyiahf/vczjk/w84;-><init>()V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    iget-object v1, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooOOOO()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/wa4;

    invoke-direct {v0}, Llyiahf/vczjk/wa4;-><init>()V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    iget-object v1, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooOoO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/hc4;->OooOoo0:Ljava/lang/String;

    if-nez v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/hc4;->o00000oo()Llyiahf/vczjk/g94;

    move-result-object v1

    instance-of v1, v1, Llyiahf/vczjk/w84;

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    add-int/lit8 v1, v1, -0x1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    throw v0
.end method

.method public final OooOoOO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/hc4;->OooOoo0:Ljava/lang/String;

    if-nez v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/hc4;->o00000oo()Llyiahf/vczjk/g94;

    move-result-object v1

    instance-of v1, v1, Llyiahf/vczjk/wa4;

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    add-int/lit8 v1, v1, -0x1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    throw v0
.end method

.method public final OooOooo(Ljava/lang/String;)V
    .locals 1

    const-string v0, "name == null"

    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/hc4;->OooOoo0:Ljava/lang/String;

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/hc4;->o00000oo()Llyiahf/vczjk/g94;

    move-result-object v0

    instance-of v0, v0, Llyiahf/vczjk/wa4;

    if-eqz v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/hc4;->OooOoo0:Ljava/lang/String;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Please begin an object before writing a name."

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Did not expect a name"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OoooO00()Llyiahf/vczjk/zc4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/va4;->OooOOO0:Llyiahf/vczjk/va4;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-object p0
.end method

.method public final close()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v1, Llyiahf/vczjk/hc4;->OooOooo:Llyiahf/vczjk/hb4;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :cond_0
    new-instance v0, Ljava/io/IOException;

    const-string v1, "Incomplete document"

    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final flush()V
    .locals 0

    return-void
.end method

.method public final o0000(Llyiahf/vczjk/g94;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/hc4;->OooOoo0:Ljava/lang/String;

    if-eqz v0, :cond_2

    instance-of v0, p1, Llyiahf/vczjk/va4;

    if-eqz v0, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/zc4;->OooOo0o:Z

    if-eqz v0, :cond_1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hc4;->o00000oo()Llyiahf/vczjk/g94;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wa4;

    iget-object v1, p0, Llyiahf/vczjk/hc4;->OooOoo0:Ljava/lang/String;

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/wa4;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/g94;)V

    :cond_1
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/hc4;->OooOoo0:Ljava/lang/String;

    return-void

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_3

    iput-object p1, p0, Llyiahf/vczjk/hc4;->OooOoo:Llyiahf/vczjk/g94;

    return-void

    :cond_3
    invoke-virtual {p0}, Llyiahf/vczjk/hc4;->o00000oo()Llyiahf/vczjk/g94;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/w84;

    if-eqz v1, :cond_4

    check-cast v0, Llyiahf/vczjk/w84;

    iget-object v0, v0, Llyiahf/vczjk/w84;->OooOOO0:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1}, Ljava/lang/IllegalStateException;-><init>()V

    throw p1
.end method

.method public final o00000O(Ljava/lang/Number;)V
    .locals 3

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/va4;->OooOOO0:Llyiahf/vczjk/va4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void

    :cond_0
    iget v0, p0, Llyiahf/vczjk/zc4;->OooOo00:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->isNaN(D)Z

    move-result v2

    if-nez v2, :cond_2

    invoke-static {v0, v1}, Ljava/lang/Double;->isInfinite(D)Z

    move-result v0

    if-nez v0, :cond_2

    :goto_0
    new-instance v0, Llyiahf/vczjk/hb4;

    invoke-direct {v0, p1}, Llyiahf/vczjk/hb4;-><init>(Ljava/lang/Number;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void

    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "JSON forbids NaN and infinities: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final o00000o0(Ljava/lang/String;)V
    .locals 1

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/va4;->OooOOO0:Llyiahf/vczjk/va4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void

    :cond_0
    new-instance v0, Llyiahf/vczjk/hb4;

    invoke-direct {v0, p1}, Llyiahf/vczjk/hb4;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void
.end method

.method public final o00000oo()Llyiahf/vczjk/g94;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    const/4 v1, 0x1

    invoke-static {v1, v0}, Llyiahf/vczjk/ix8;->OooO0Oo(ILjava/util/ArrayList;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/g94;

    return-object v0
.end method

.method public final o0000Ooo(Z)V
    .locals 1

    new-instance v0, Llyiahf/vczjk/hb4;

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/hb4;-><init>(Ljava/lang/Boolean;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void
.end method

.method public final o000OOo(Ljava/lang/Boolean;)V
    .locals 1

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/va4;->OooOOO0:Llyiahf/vczjk/va4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void

    :cond_0
    new-instance v0, Llyiahf/vczjk/hb4;

    invoke-direct {v0, p1}, Llyiahf/vczjk/hb4;-><init>(Ljava/lang/Boolean;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void
.end method

.method public final o00oO0o(D)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/zc4;->OooOo00:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p1, p2}, Ljava/lang/Double;->isNaN(D)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-static {p1, p2}, Ljava/lang/Double;->isInfinite(D)Z

    move-result v0

    if-nez v0, :cond_1

    :goto_0
    new-instance v0, Llyiahf/vczjk/hb4;

    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/hb4;-><init>(Ljava/lang/Number;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void

    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "JSON forbids NaN and infinities: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1, p2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final o0ooOO0(J)V
    .locals 1

    new-instance v0, Llyiahf/vczjk/hb4;

    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/hb4;-><init>(Ljava/lang/Number;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc4;->o0000(Llyiahf/vczjk/g94;)V

    return-void
.end method
