.class public final Llyiahf/vczjk/zo4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/e89;


# instance fields
.field public OooOOO:F

.field public OooOOO0:Llyiahf/vczjk/yn4;

.field public OooOOOO:F

.field public final synthetic OooOOOo:Llyiahf/vczjk/fp4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fp4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zo4;->OooOOOo:Llyiahf/vczjk/fp4;

    sget-object p1, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    iput-object p1, p0, Llyiahf/vczjk/zo4;->OooOOO0:Llyiahf/vczjk/yn4;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/util/List;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/zo4;->OooOOOo:Llyiahf/vczjk/fp4;

    invoke-virtual {v0}, Llyiahf/vczjk/fp4;->OooO0Oo()V

    iget-object v1, v0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    iget-object v2, v1, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v2, v2, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    sget-object v3, Llyiahf/vczjk/lo4;->OooOOO0:Llyiahf/vczjk/lo4;

    if-eq v2, v3, :cond_1

    sget-object v4, Llyiahf/vczjk/lo4;->OooOOOO:Llyiahf/vczjk/lo4;

    if-eq v2, v4, :cond_1

    sget-object v4, Llyiahf/vczjk/lo4;->OooOOO:Llyiahf/vczjk/lo4;

    if-eq v2, v4, :cond_1

    sget-object v4, Llyiahf/vczjk/lo4;->OooOOOo:Llyiahf/vczjk/lo4;

    if-ne v2, v4, :cond_0

    goto :goto_0

    :cond_0
    const-string v4, "subcompose can only be used inside the measure or layout blocks"

    invoke-static {v4}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_1
    :goto_0
    iget-object v4, v0, Llyiahf/vczjk/fp4;->OooOOoo:Llyiahf/vczjk/js5;

    invoke-virtual {v4, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    const/4 v6, 0x0

    const/4 v7, 0x1

    if-nez v5, :cond_5

    iget-object v5, v0, Llyiahf/vczjk/fp4;->OooOo0O:Llyiahf/vczjk/js5;

    invoke-virtual {v5, p1}, Llyiahf/vczjk/js5;->OooOO0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ro4;

    if-eqz v5, :cond_3

    iget v8, v0, Llyiahf/vczjk/fp4;->OooOoOO:I

    if-lez v8, :cond_2

    goto :goto_1

    :cond_2
    const-string v8, "Check failed."

    invoke-static {v8}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_1
    iget v8, v0, Llyiahf/vczjk/fp4;->OooOoOO:I

    add-int/lit8 v8, v8, -0x1

    iput v8, v0, Llyiahf/vczjk/fp4;->OooOoOO:I

    goto :goto_2

    :cond_3
    invoke-virtual {v0, p1}, Llyiahf/vczjk/fp4;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/ro4;

    move-result-object v5

    if-nez v5, :cond_4

    iget v5, v0, Llyiahf/vczjk/fp4;->OooOOOo:I

    new-instance v8, Llyiahf/vczjk/ro4;

    const/4 v9, 0x2

    invoke-direct {v8, v9}, Llyiahf/vczjk/ro4;-><init>(I)V

    iput-boolean v7, v1, Llyiahf/vczjk/ro4;->OooOoo:Z

    invoke-virtual {v1, v5, v8}, Llyiahf/vczjk/ro4;->OooOoo0(ILlyiahf/vczjk/ro4;)V

    iput-boolean v6, v1, Llyiahf/vczjk/ro4;->OooOoo:Z

    move-object v5, v8

    :cond_4
    :goto_2
    invoke-virtual {v4, p1, v5}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_5
    check-cast v5, Llyiahf/vczjk/ro4;

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v4

    iget v8, v0, Llyiahf/vczjk/fp4;->OooOOOo:I

    invoke-static {v8, v4}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v4

    if-eq v4, v5, :cond_7

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ts5;

    iget-object v4, v4, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/ws5;->OooO(Ljava/lang/Object;)I

    move-result v4

    iget v8, v0, Llyiahf/vczjk/fp4;->OooOOOo:I

    if-lt v4, v8, :cond_6

    goto :goto_3

    :cond_6
    new-instance v8, Ljava/lang/StringBuilder;

    const-string v9, "Key \""

    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v8, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v9, "\" was already used. If you are using LazyColumn/Row please make sure you provide a unique key for each item."

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :goto_3
    iget v8, v0, Llyiahf/vczjk/fp4;->OooOOOo:I

    if-eq v8, v4, :cond_7

    iput-boolean v7, v1, Llyiahf/vczjk/ro4;->OooOoo:Z

    invoke-virtual {v1, v4, v8, v7}, Llyiahf/vczjk/ro4;->Oooo0o0(III)V

    iput-boolean v6, v1, Llyiahf/vczjk/ro4;->OooOoo:Z

    :cond_7
    iget v1, v0, Llyiahf/vczjk/fp4;->OooOOOo:I

    add-int/2addr v1, v7

    iput v1, v0, Llyiahf/vczjk/fp4;->OooOOOo:I

    invoke-virtual {v0, v5, p1, p2}, Llyiahf/vczjk/fp4;->OooO0oO(Llyiahf/vczjk/ro4;Ljava/lang/Object;Llyiahf/vczjk/ze3;)V

    if-eq v2, v3, :cond_9

    sget-object p1, Llyiahf/vczjk/lo4;->OooOOOO:Llyiahf/vczjk/lo4;

    if-ne v2, p1, :cond_8

    goto :goto_4

    :cond_8
    invoke-virtual {v5}, Llyiahf/vczjk/ro4;->OooOOO0()Ljava/util/List;

    move-result-object p1

    return-object p1

    :cond_9
    :goto_4
    invoke-virtual {v5}, Llyiahf/vczjk/ro4;->OooOOO()Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0O0()F
    .locals 1

    iget v0, p0, Llyiahf/vczjk/zo4;->OooOOO:F

    return v0
.end method

.method public final OooOo(IILjava/util/Map;Llyiahf/vczjk/ow;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;
    .locals 9

    const/high16 v0, -0x1000000

    and-int v1, p1, v0

    if-nez v1, :cond_0

    and-int/2addr v0, p2

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Size("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, " x "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ") is out of range. Each dimension must be between 0 and 16777215."

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    new-instance v1, Llyiahf/vczjk/yo4;

    iget-object v7, p0, Llyiahf/vczjk/zo4;->OooOOOo:Llyiahf/vczjk/fp4;

    move-object v6, p0

    move v2, p1

    move v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v8, p5

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/yo4;-><init>(IILjava/util/Map;Llyiahf/vczjk/ow;Llyiahf/vczjk/zo4;Llyiahf/vczjk/fp4;Llyiahf/vczjk/oe3;)V

    return-object v1
.end method

.method public final OoooOo0()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zo4;->OooOOOo:Llyiahf/vczjk/fp4;

    iget-object v0, v0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    sget-object v1, Llyiahf/vczjk/lo4;->OooOOOo:Llyiahf/vczjk/lo4;

    if-eq v0, v1, :cond_1

    sget-object v1, Llyiahf/vczjk/lo4;->OooOOO:Llyiahf/vczjk/lo4;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final getLayoutDirection()Llyiahf/vczjk/yn4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zo4;->OooOOO0:Llyiahf/vczjk/yn4;

    return-object v0
.end method

.method public final o000oOoO()F
    .locals 1

    iget v0, p0, Llyiahf/vczjk/zo4;->OooOOOO:F

    return v0
.end method
