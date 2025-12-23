.class public final Llyiahf/vczjk/k56;
.super Llyiahf/vczjk/r56;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/k56;

.field public static final OooOOOo:Llyiahf/vczjk/k56;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/k56;

    const/4 v1, 0x0

    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object v1

    sget-object v2, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/k56;-><init>(Ljava/lang/Class;Ljava/lang/Byte;)V

    sput-object v0, Llyiahf/vczjk/k56;->OooOOOO:Llyiahf/vczjk/k56;

    new-instance v0, Llyiahf/vczjk/k56;

    const-class v1, Ljava/lang/Byte;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/k56;-><init>(Ljava/lang/Class;Ljava/lang/Byte;)V

    sput-object v0, Llyiahf/vczjk/k56;->OooOOOo:Llyiahf/vczjk/k56;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;Ljava/lang/Byte;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object v0

    invoke-direct {p0, p2, v0, p1}, Llyiahf/vczjk/r56;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Class;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooo0oO()B

    move-result p1

    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    const/4 v3, 0x0

    if-ne v1, v2, :cond_4

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p2

    const-string v0, "null"

    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOo00(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Byte;

    return-object p1

    :cond_1
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_2

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOOo0(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Byte;

    return-object p1

    :cond_2
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/m49;->Oooo(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    const/4 v0, 0x0

    :try_start_0
    invoke-static {p2}, Llyiahf/vczjk/u56;->OooO0Oo(Ljava/lang/String;)I

    move-result v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    const/16 v2, -0x80

    if-lt v1, v2, :cond_3

    const/16 v2, 0xff

    if-gt v1, v2, :cond_3

    int-to-byte p1, v1

    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object p1

    return-object p1

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    const-string v2, "overflow, value cannot be represented as 8-bit value"

    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {p1, v1, p2, v2, v0}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :catch_0
    iget-object v1, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    const-string v2, "not a valid Byte value"

    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {p1, v1, p2, v2, v0}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_4
    sget-object v2, Llyiahf/vczjk/gc4;->OooOo0O:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_6

    sget-object v0, Llyiahf/vczjk/w72;->Oooo00o:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooo0oO()B

    move-result p1

    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object p1

    return-object p1

    :cond_5
    const-string v0, "Byte"

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m49;->OooOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/String;)V

    throw v3

    :cond_6
    sget-object v2, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_7

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOOoo(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Byte;

    return-object p1

    :cond_7
    sget-object v2, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_8

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOo0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Byte;

    return-object p1

    :cond_8
    if-ne v1, v0, :cond_9

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooo0oO()B

    move-result p1

    invoke-static {p1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object p1

    return-object p1

    :cond_9
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v3
.end method
