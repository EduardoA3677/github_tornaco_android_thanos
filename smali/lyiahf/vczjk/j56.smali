.class public final Llyiahf/vczjk/j56;
.super Llyiahf/vczjk/r56;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/j56;

.field public static final OooOOOo:Llyiahf/vczjk/j56;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/j56;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    sget-object v2, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/j56;-><init>(Ljava/lang/Class;Ljava/lang/Boolean;)V

    sput-object v0, Llyiahf/vczjk/j56;->OooOOOO:Llyiahf/vczjk/j56;

    new-instance v0, Llyiahf/vczjk/j56;

    const-class v1, Ljava/lang/Boolean;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/j56;-><init>(Ljava/lang/Class;Ljava/lang/Boolean;)V

    sput-object v0, Llyiahf/vczjk/j56;->OooOOOo:Llyiahf/vczjk/j56;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;Ljava/lang/Boolean;)V
    .locals 1

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-direct {p0, p2, v0, p1}, Llyiahf/vczjk/r56;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Class;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo0o:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :cond_0
    sget-object v1, Llyiahf/vczjk/gc4;->OooOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_1

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :cond_1
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/j56;->OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object p3

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo0o:Llyiahf/vczjk/gc4;

    if-ne p3, v0, :cond_0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/gc4;->OooOo:Llyiahf/vczjk/gc4;

    if-ne p3, v0, :cond_1

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :cond_1
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/j56;->OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Boolean;
    .locals 4

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOOoo(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    return-object p1

    :cond_0
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_1

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOo0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    return-object p1

    :cond_1
    sget-object v1, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    const-string p1, "0"

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    xor-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :cond_2
    sget-object v1, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    if-ne v0, v1, :cond_9

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p2

    const-string v0, "true"

    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8

    const-string v0, "True"

    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    goto :goto_1

    :cond_3
    const-string v0, "false"

    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7

    const-string v0, "False"

    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    goto :goto_0

    :cond_4
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_5

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOOo0(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    return-object p1

    :cond_5
    const-string v0, "null"

    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_6

    iget-boolean p2, p0, Llyiahf/vczjk/r56;->_primitive:Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOo00(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    return-object p1

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v3, "only \"true\" or \"false\" recognized"

    invoke-virtual {p1, v0, p2, v3, v1}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2

    :cond_7
    :goto_0
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/m49;->Oooo(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :cond_8
    :goto_1
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/m49;->Oooo(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :cond_9
    sget-object v1, Llyiahf/vczjk/gc4;->OooOo0o:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_a

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :cond_a
    sget-object v1, Llyiahf/vczjk/gc4;->OooOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_b

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :cond_b
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2
.end method
