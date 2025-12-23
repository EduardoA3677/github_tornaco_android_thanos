.class public final Llyiahf/vczjk/o56;
.super Llyiahf/vczjk/r56;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/o56;

.field public static final OooOOOo:Llyiahf/vczjk/o56;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/o56;

    const/4 v1, 0x0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    sget-object v2, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/o56;-><init>(Ljava/lang/Class;Ljava/lang/Integer;)V

    sput-object v0, Llyiahf/vczjk/o56;->OooOOOO:Llyiahf/vczjk/o56;

    new-instance v0, Llyiahf/vczjk/o56;

    const-class v1, Ljava/lang/Integer;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/o56;-><init>(Ljava/lang/Class;Ljava/lang/Integer;)V

    sput-object v0, Llyiahf/vczjk/o56;->OooOOOo:Llyiahf/vczjk/o56;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;Ljava/lang/Integer;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-direct {p0, p2, v0, p1}, Llyiahf/vczjk/r56;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Class;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/o56;->OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    sget-object p3, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, p3}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result p3

    if-eqz p3, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/o56;->OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Integer;
    .locals 6

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    const/4 v1, 0x3

    if-eq v0, v1, :cond_b

    const/16 v1, 0xb

    if-eq v0, v1, :cond_a

    const/4 v1, 0x6

    const/4 v2, 0x0

    if-eq v0, v1, :cond_3

    const/4 v1, 0x7

    if-eq v0, v1, :cond_2

    const/16 v1, 0x8

    if-ne v0, v1, :cond_1

    sget-object v0, Llyiahf/vczjk/w72;->Oooo00o:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000OO()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :cond_0
    const-string v0, "Integer"

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m49;->OooOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/String;)V

    throw v2

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :cond_3
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_4

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOOo0(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    return-object p1

    :cond_4
    const-string v1, "null"

    invoke-virtual {v1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOo00(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    return-object p1

    :cond_5
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/m49;->Oooo(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    const/16 v1, 0x9

    const/4 v3, 0x0

    if-le v0, v1, :cond_9

    :try_start_0
    invoke-static {p2}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v0

    const-wide/32 v4, -0x80000000

    cmp-long v4, v0, v4

    if-ltz v4, :cond_7

    const-wide/32 v4, 0x7fffffff

    cmp-long v4, v0, v4

    if-lez v4, :cond_6

    goto :goto_0

    :cond_6
    move v4, v3

    goto :goto_1

    :cond_7
    :goto_0
    const/4 v4, 0x1

    :goto_1
    if-nez v4, :cond_8

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :cond_8
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    const-string v1, "Overflow: numeric value (%s) out of range of Integer (%d - %d)"

    const/high16 v4, -0x80000000

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    const v5, 0x7fffffff

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    filled-new-array {p2, v4, v5}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v1, v4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    new-array v4, v3, [Ljava/lang/Object;

    invoke-virtual {p1, v0, p2, v1, v4}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2

    :cond_9
    invoke-static {p2}, Llyiahf/vczjk/u56;->OooO0Oo(Ljava/lang/String;)I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    const-string v1, "not a valid Integer value"

    new-array v3, v3, [Ljava/lang/Object;

    invoke-virtual {p1, v0, p2, v1, v3}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2

    :cond_a
    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOOoo(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    return-object p1

    :cond_b
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOo0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    return-object p1
.end method
