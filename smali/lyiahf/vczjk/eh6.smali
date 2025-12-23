.class public final Llyiahf/vczjk/eh6;
.super Llyiahf/vczjk/eb0;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Comparable;


# static fields
.field public static final OooOoO0:Llyiahf/vczjk/xn;


# instance fields
.field public final OooOOO:Z

.field public final OooOOOO:Llyiahf/vczjk/fc5;

.field public final OooOOOo:Llyiahf/vczjk/yn;

.field public final OooOOo:Llyiahf/vczjk/xa7;

.field public final OooOOo0:Llyiahf/vczjk/xa7;

.field public OooOOoo:Llyiahf/vczjk/rq;

.field public transient OooOo:Llyiahf/vczjk/xn;

.field public OooOo0:Llyiahf/vczjk/rq;

.field public OooOo00:Llyiahf/vczjk/rq;

.field public OooOo0O:Llyiahf/vczjk/rq;

.field public transient OooOo0o:Llyiahf/vczjk/wa7;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/xn;

    const/4 v1, 0x1

    const-string v2, ""

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/xn;-><init>(ILjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/eh6;->OooOoO0:Llyiahf/vczjk/xn;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/eh6;Llyiahf/vczjk/xa7;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/eh6;->OooOOOO:Llyiahf/vczjk/fc5;

    iput-object v0, p0, Llyiahf/vczjk/eh6;->OooOOOO:Llyiahf/vczjk/fc5;

    iget-object v0, p1, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    iput-object v0, p0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    iget-object v0, p1, Llyiahf/vczjk/eh6;->OooOOo:Llyiahf/vczjk/xa7;

    iput-object v0, p0, Llyiahf/vczjk/eh6;->OooOOo:Llyiahf/vczjk/xa7;

    iput-object p2, p0, Llyiahf/vczjk/eh6;->OooOOo0:Llyiahf/vczjk/xa7;

    iget-object p2, p1, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    iput-object p2, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    iget-object p2, p1, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    iput-object p2, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    iget-object p2, p1, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    iput-object p2, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    iget-object p2, p1, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    iput-object p2, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    iget-boolean p1, p1, Llyiahf/vczjk/eh6;->OooOOO:Z

    iput-boolean p1, p0, Llyiahf/vczjk/eh6;->OooOOO:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/fc5;Llyiahf/vczjk/yn;ZLlyiahf/vczjk/xa7;Llyiahf/vczjk/xa7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/eh6;->OooOOOO:Llyiahf/vczjk/fc5;

    iput-object p2, p0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    iput-object p4, p0, Llyiahf/vczjk/eh6;->OooOOo:Llyiahf/vczjk/xa7;

    iput-object p5, p0, Llyiahf/vczjk/eh6;->OooOOo0:Llyiahf/vczjk/xa7;

    iput-boolean p3, p0, Llyiahf/vczjk/eh6;->OooOOO:Z

    return-void
.end method

.method public static OooOoOO(Llyiahf/vczjk/rq;)Z
    .locals 1

    :goto_0
    if-eqz p0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/rq;->OooO0OO:Ljava/io/Serializable;

    check-cast v0, Llyiahf/vczjk/xa7;

    if-eqz v0, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/rq;->OooO0Oo:Z

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    iget-object p0, p0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOoo(Llyiahf/vczjk/rq;)Z
    .locals 1

    :goto_0
    if-eqz p0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/rq;->OooO0o:Z

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    iget-object p0, p0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOoo0(Llyiahf/vczjk/rq;)Z
    .locals 1

    :goto_0
    if-eqz p0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/rq;->OooO0OO:Ljava/io/Serializable;

    check-cast v0, Llyiahf/vczjk/xa7;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/xa7;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    iget-object p0, p0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOooO(Llyiahf/vczjk/rq;)Z
    .locals 1

    :goto_0
    if-eqz p0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/rq;->OooO0o0:Z

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    iget-object p0, p0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOooo(Llyiahf/vczjk/rq;Llyiahf/vczjk/ao;)Llyiahf/vczjk/rq;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pm;->o0Oo0oo(Llyiahf/vczjk/ao;)Llyiahf/vczjk/u34;

    move-result-object v0

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/pm;

    iget-object v0, p0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rq;

    if-eqz v0, :cond_0

    invoke-static {v0, p1}, Llyiahf/vczjk/eh6;->OooOooo(Llyiahf/vczjk/rq;Llyiahf/vczjk/ao;)Llyiahf/vczjk/rq;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/rq;->OooO0o(Llyiahf/vczjk/rq;)Llyiahf/vczjk/rq;

    move-result-object p0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/pm;

    if-ne v2, p1, :cond_1

    return-object p0

    :cond_1
    new-instance v1, Llyiahf/vczjk/rq;

    iget-boolean v6, p0, Llyiahf/vczjk/rq;->OooO0o0:Z

    iget-boolean v7, p0, Llyiahf/vczjk/rq;->OooO0o:Z

    iget-object p1, p0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/rq;

    iget-object p1, p0, Llyiahf/vczjk/rq;->OooO0OO:Ljava/io/Serializable;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/xa7;

    iget-boolean v5, p0, Llyiahf/vczjk/rq;->OooO0Oo:Z

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/rq;-><init>(Llyiahf/vczjk/pm;Llyiahf/vczjk/rq;Llyiahf/vczjk/xa7;ZZZ)V

    return-object v1
.end method

.method public static Oooo0(Llyiahf/vczjk/rm;)I
    .locals 2

    iget-object p0, p0, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {p0}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object p0

    const-string v0, "get"

    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v0

    const/4 v1, 0x3

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    if-le v0, v1, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const-string v0, "is"

    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p0

    const/4 v0, 0x2

    if-le p0, v0, :cond_1

    return v0

    :cond_1
    return v1
.end method

.method public static Oooo00O(Llyiahf/vczjk/rq;Ljava/util/Set;)Ljava/util/Set;
    .locals 1

    :goto_0
    if-eqz p0, :cond_3

    iget-boolean v0, p0, Llyiahf/vczjk/rq;->OooO0Oo:Z

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/rq;->OooO0OO:Ljava/io/Serializable;

    check-cast v0, Llyiahf/vczjk/xa7;

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    if-nez p1, :cond_1

    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    :cond_1
    invoke-interface {p1, v0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    :cond_2
    :goto_1
    iget-object p0, p0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_3
    return-object p1
.end method

.method public static Oooo00o(Llyiahf/vczjk/rq;)Llyiahf/vczjk/ao;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    iget-object v0, v0, Llyiahf/vczjk/pm;->OooOo0O:Llyiahf/vczjk/ao;

    iget-object p0, p0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/rq;

    if-eqz p0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/eh6;->Oooo00o(Llyiahf/vczjk/rq;)Llyiahf/vczjk/ao;

    move-result-object p0

    invoke-static {v0, p0}, Llyiahf/vczjk/ao;->OooO0O0(Llyiahf/vczjk/ao;Llyiahf/vczjk/ao;)Llyiahf/vczjk/ao;

    move-result-object p0

    return-object p0

    :cond_0
    return-object v0
.end method

.method public static varargs Oooo0O0(I[Llyiahf/vczjk/rq;)Llyiahf/vczjk/ao;
    .locals 2

    aget-object v0, p1, p0

    invoke-static {v0}, Llyiahf/vczjk/eh6;->Oooo00o(Llyiahf/vczjk/rq;)Llyiahf/vczjk/ao;

    move-result-object v0

    :cond_0
    add-int/lit8 p0, p0, 0x1

    array-length v1, p1

    if-ge p0, v1, :cond_1

    aget-object v1, p1, p0

    if-eqz v1, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/eh6;->Oooo0O0(I[Llyiahf/vczjk/rq;)Llyiahf/vczjk/ao;

    move-result-object p0

    invoke-static {v0, p0}, Llyiahf/vczjk/ao;->OooO0O0(Llyiahf/vczjk/ao;Llyiahf/vczjk/ao;)Llyiahf/vczjk/ao;

    move-result-object p0

    return-object p0

    :cond_1
    return-object v0
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/xn;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo:Llyiahf/vczjk/xn;

    sget-object v1, Llyiahf/vczjk/eh6;->OooOoO0:Llyiahf/vczjk/xn;

    if-eqz v0, :cond_1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x0

    :cond_0
    return-object v0

    :cond_1
    new-instance v0, Llyiahf/vczjk/ah6;

    const/4 v2, 0x0

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/ah6;-><init>(Llyiahf/vczjk/eh6;I)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/eh6;->Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xn;

    if-nez v0, :cond_2

    goto :goto_0

    :cond_2
    move-object v1, v0

    :goto_0
    iput-object v1, p0, Llyiahf/vczjk/eh6;->OooOo:Llyiahf/vczjk/xn;

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/wa7;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0o:Llyiahf/vczjk/wa7;

    if-nez v0, :cond_15

    new-instance v0, Llyiahf/vczjk/bh6;

    invoke-direct {v0, p0}, Llyiahf/vczjk/bh6;-><init>(Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/eh6;->Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    new-instance v1, Llyiahf/vczjk/tg7;

    const/16 v2, 0x19

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p0, v1}, Llyiahf/vczjk/eh6;->Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;

    move-result-object v1

    move-object v4, v1

    check-cast v4, Ljava/lang/String;

    new-instance v1, Llyiahf/vczjk/sw7;

    const/16 v2, 0x1b

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/sw7;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p0, v1}, Llyiahf/vczjk/eh6;->Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    new-instance v2, Llyiahf/vczjk/zg6;

    const/4 v3, 0x1

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/zg6;-><init>(Llyiahf/vczjk/eh6;I)V

    invoke-virtual {p0, v2}, Llyiahf/vczjk/eh6;->Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    if-nez v0, :cond_1

    if-nez v1, :cond_1

    if-nez v2, :cond_1

    sget-object v0, Llyiahf/vczjk/wa7;->OooOOOo:Llyiahf/vczjk/wa7;

    if-nez v4, :cond_0

    goto :goto_0

    :cond_0
    new-instance v2, Llyiahf/vczjk/wa7;

    iget-object v3, v0, Llyiahf/vczjk/wa7;->_required:Ljava/lang/Boolean;

    iget-object v5, v0, Llyiahf/vczjk/wa7;->_index:Ljava/lang/Integer;

    iget-object v6, v0, Llyiahf/vczjk/wa7;->_defaultValue:Ljava/lang/String;

    iget-object v8, v0, Llyiahf/vczjk/wa7;->_valueNulls:Llyiahf/vczjk/d56;

    iget-object v9, v0, Llyiahf/vczjk/wa7;->_contentNulls:Llyiahf/vczjk/d56;

    iget-object v7, v0, Llyiahf/vczjk/wa7;->OooOOO0:Llyiahf/vczjk/pc0;

    invoke-direct/range {v2 .. v9}, Llyiahf/vczjk/wa7;-><init>(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/pc0;Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    move-object v0, v2

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0o:Llyiahf/vczjk/wa7;

    goto :goto_1

    :cond_1
    invoke-static {v0, v4, v1, v2}, Llyiahf/vczjk/wa7;->OooO00o(Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)Llyiahf/vczjk/wa7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0o:Llyiahf/vczjk/wa7;

    :goto_1
    iget-boolean v0, p0, Llyiahf/vczjk/eh6;->OooOOO:Z

    if-nez v0, :cond_15

    iget-object v1, p0, Llyiahf/vczjk/eh6;->OooOo0o:Llyiahf/vczjk/wa7;

    const/4 v2, 0x0

    if-eqz v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    goto :goto_2

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    goto :goto_2

    :cond_3
    move-object v0, v2

    goto :goto_2

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_5

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    goto :goto_2

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_6

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    goto :goto_2

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_7

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    goto :goto_2

    :cond_7
    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    :goto_2
    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOO0O()Llyiahf/vczjk/pm;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/eh6;->OooOOOO:Llyiahf/vczjk/fc5;

    const/4 v5, 0x1

    if-eqz v0, :cond_d

    iget-object v6, p0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    const/4 v7, 0x0

    if-eqz v6, :cond_a

    if-eqz v3, :cond_9

    invoke-virtual {v6, v0}, Llyiahf/vczjk/yn;->OooOo00(Llyiahf/vczjk/pm;)Ljava/lang/Boolean;

    move-result-object v2

    if-eqz v2, :cond_9

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-eqz v2, :cond_8

    new-instance v2, Llyiahf/vczjk/pc0;

    const/16 v8, 0x8

    invoke-direct {v2, v8, v3, v7}, Llyiahf/vczjk/pc0;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/wa7;->OooO0OO(Llyiahf/vczjk/pc0;)Llyiahf/vczjk/wa7;

    move-result-object v1

    :cond_8
    move v2, v7

    goto :goto_3

    :cond_9
    move v2, v5

    :goto_3
    invoke-virtual {v6, v0}, Llyiahf/vczjk/yn;->OoooO(Llyiahf/vczjk/pm;)Llyiahf/vczjk/ac4;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/ac4;->OooO0O0()Llyiahf/vczjk/d56;

    move-result-object v8

    invoke-virtual {v6}, Llyiahf/vczjk/ac4;->OooO00o()Llyiahf/vczjk/d56;

    move-result-object v6

    goto :goto_4

    :cond_a
    move-object v6, v2

    move-object v8, v6

    move v2, v5

    :goto_4
    if-nez v2, :cond_b

    if-eqz v8, :cond_b

    if-nez v6, :cond_e

    :cond_b
    instance-of v9, v0, Llyiahf/vczjk/rm;

    if-eqz v9, :cond_c

    move-object v9, v0

    check-cast v9, Llyiahf/vczjk/rm;

    invoke-virtual {v9}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v10

    array-length v10, v10

    if-lez v10, :cond_c

    invoke-virtual {v9, v7}, Llyiahf/vczjk/rm;->o000000O(I)Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    goto :goto_5

    :cond_c
    invoke-virtual {v0}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    :goto_5
    invoke-virtual {v4, v0}, Llyiahf/vczjk/fc5;->OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;

    goto :goto_6

    :cond_d
    move-object v6, v2

    move-object v8, v6

    move v2, v5

    :cond_e
    :goto_6
    if-nez v2, :cond_f

    if-eqz v8, :cond_f

    if-nez v6, :cond_12

    :cond_f
    invoke-virtual {v4}, Llyiahf/vczjk/fc5;->OooOoo0()Llyiahf/vczjk/ac4;

    move-result-object v0

    if-nez v8, :cond_10

    invoke-virtual {v0}, Llyiahf/vczjk/ac4;->OooO0O0()Llyiahf/vczjk/d56;

    move-result-object v8

    :cond_10
    if-nez v6, :cond_11

    invoke-virtual {v0}, Llyiahf/vczjk/ac4;->OooO00o()Llyiahf/vczjk/d56;

    move-result-object v6

    :cond_11
    if-eqz v2, :cond_12

    iget-object v0, v4, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object v0, v0, Llyiahf/vczjk/vh1;->_defaultMergeable:Ljava/lang/Boolean;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-virtual {v2, v0}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_12

    if-eqz v3, :cond_12

    new-instance v0, Llyiahf/vczjk/pc0;

    const/16 v2, 0x8

    invoke-direct {v0, v2, v3, v5}, Llyiahf/vczjk/pc0;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/wa7;->OooO0OO(Llyiahf/vczjk/pc0;)Llyiahf/vczjk/wa7;

    move-result-object v1

    :cond_12
    if-nez v8, :cond_13

    if-eqz v6, :cond_14

    :cond_13
    invoke-virtual {v1, v8, v6}, Llyiahf/vczjk/wa7;->OooO0Oo(Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)Llyiahf/vczjk/wa7;

    move-result-object v1

    :cond_14
    iput-object v1, p0, Llyiahf/vczjk/eh6;->OooOo0o:Llyiahf/vczjk/wa7;

    :cond_15
    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0o:Llyiahf/vczjk/wa7;

    return-object v0
.end method

.method public final OooO0o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/fa4;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOO0O()Llyiahf/vczjk/pm;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    if-nez v1, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {v1, v0}, Llyiahf/vczjk/yn;->Oooo0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/fa4;

    move-result-object v0

    :goto_0
    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    :cond_1
    return-object v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/t66;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ah6;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/ah6;-><init>(Llyiahf/vczjk/eh6;I)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/eh6;->Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/t66;

    return-object v0
.end method

.method public final OooOO0()[Ljava/lang/Class;
    .locals 2

    new-instance v0, Llyiahf/vczjk/zg6;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/zg6;-><init>(Llyiahf/vczjk/eh6;I)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/eh6;->Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Ljava/lang/Class;

    return-object v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/vm;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/pm;

    check-cast v1, Llyiahf/vczjk/vm;

    iget-object v2, v1, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    instance-of v2, v2, Llyiahf/vczjk/jm;

    if-eqz v2, :cond_1

    return-object v1

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rq;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    check-cast v0, Llyiahf/vczjk/vm;

    return-object v0
.end method

.method public final OooOOO()Llyiahf/vczjk/mm;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/pm;

    check-cast v1, Llyiahf/vczjk/mm;

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rq;

    :goto_0
    if-eqz v0, :cond_3

    iget-object v2, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pm;

    check-cast v2, Llyiahf/vczjk/mm;

    iget-object v3, v1, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v3}, Ljava/lang/reflect/Field;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v3

    iget-object v4, v2, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v4

    if-eq v3, v4, :cond_2

    invoke-virtual {v3, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_1

    move-object v1, v2

    goto :goto_1

    :cond_1
    invoke-virtual {v4, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_2

    :goto_1
    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Multiple fields representing property \""

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->getName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, "\": "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Llyiahf/vczjk/pm;->o00oO0O()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " vs "

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Llyiahf/vczjk/pm;->o00oO0O()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_3
    return-object v1
.end method

.method public final OooOOO0()Ljava/util/Iterator;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/vy0;->OooO0OO:Ljava/util/Iterator;

    return-object v0

    :cond_0
    new-instance v1, Llyiahf/vczjk/ch6;

    const/4 v2, 0x0

    invoke-direct {v1, v2}, Llyiahf/vczjk/ch6;-><init>(I)V

    iput-object v0, v1, Llyiahf/vczjk/ch6;->OooOOO:Ljava/lang/Object;

    return-object v1
.end method

.method public final OooOOOO()Llyiahf/vczjk/rm;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rq;

    if-nez v1, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    check-cast v0, Llyiahf/vczjk/rm;

    return-object v0

    :cond_1
    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/pm;

    if-eqz v1, :cond_6

    check-cast v4, Llyiahf/vczjk/rm;

    iget-object v2, v4, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v2}, Ljava/lang/reflect/Method;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v2

    iget-object v3, v1, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/pm;

    check-cast v3, Llyiahf/vczjk/rm;

    iget-object v5, v3, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v5}, Ljava/lang/reflect/Method;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v5

    if-eq v2, v5, :cond_3

    invoke-virtual {v2, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v6

    if-eqz v6, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v5, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v2

    if-eqz v2, :cond_3

    goto :goto_2

    :cond_3
    invoke-static {v3}, Llyiahf/vczjk/eh6;->Oooo0(Llyiahf/vczjk/rm;)I

    move-result v2

    invoke-static {v4}, Llyiahf/vczjk/eh6;->Oooo0(Llyiahf/vczjk/rm;)I

    move-result v5

    if-eq v2, v5, :cond_5

    if-ge v2, v5, :cond_4

    :goto_1
    move-object v0, v1

    :cond_4
    :goto_2
    iget-object v1, v1, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_5
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Conflicting getter definitions for property \""

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "\": "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Llyiahf/vczjk/rm;->o00oO0O()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " vs "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Llyiahf/vczjk/rm;->o00oO0O()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_6
    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rq;

    if-nez v1, :cond_7

    goto :goto_3

    :cond_7
    new-instance v3, Llyiahf/vczjk/rq;

    iget-boolean v8, v0, Llyiahf/vczjk/rq;->OooO0o0:Z

    iget-boolean v9, v0, Llyiahf/vczjk/rq;->OooO0o:Z

    const/4 v5, 0x0

    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0OO:Ljava/io/Serializable;

    move-object v6, v1

    check-cast v6, Llyiahf/vczjk/xa7;

    iget-boolean v7, v0, Llyiahf/vczjk/rq;->OooO0Oo:Z

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/rq;-><init>(Llyiahf/vczjk/pm;Llyiahf/vczjk/rq;Llyiahf/vczjk/xa7;ZZZ)V

    move-object v0, v3

    :goto_3
    iput-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    check-cast v4, Llyiahf/vczjk/rm;

    return-object v4
.end method

.method public final OooOOOo()Llyiahf/vczjk/x64;
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/eh6;->OooOOO:Z

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOOOO()Llyiahf/vczjk/rm;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOOO()Llyiahf/vczjk/mm;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v0

    return-object v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v0

    return-object v0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOO0o()Llyiahf/vczjk/vm;

    move-result-object v0

    if-nez v0, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOOo()Llyiahf/vczjk/rm;

    move-result-object v0

    if-eqz v0, :cond_2

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/rm;->o000000O(I)Llyiahf/vczjk/x64;

    move-result-object v0

    return-object v0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOOO()Llyiahf/vczjk/mm;

    move-result-object v0

    :cond_3
    if-nez v0, :cond_4

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOOOO()Llyiahf/vczjk/rm;

    move-result-object v0

    if-nez v0, :cond_4

    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v0

    return-object v0

    :cond_4
    invoke-virtual {v0}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOo()Llyiahf/vczjk/rm;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rq;

    if-nez v1, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    check-cast v0, Llyiahf/vczjk/rm;

    return-object v0

    :cond_1
    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/pm;

    if-eqz v1, :cond_a

    check-cast v4, Llyiahf/vczjk/rm;

    iget-object v2, v4, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v2}, Ljava/lang/reflect/Method;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v2

    iget-object v3, v1, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/pm;

    check-cast v3, Llyiahf/vczjk/rm;

    iget-object v5, v3, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v5}, Ljava/lang/reflect/Method;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v5

    if-eq v2, v5, :cond_3

    invoke-virtual {v2, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v6

    if-eqz v6, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v5, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v2

    if-eqz v2, :cond_3

    goto :goto_3

    :cond_3
    iget-object v2, v3, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v2}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v2

    const-string v5, "set"

    invoke-virtual {v2, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    const/4 v7, 0x2

    const/4 v8, 0x1

    const/4 v9, 0x3

    if-eqz v6, :cond_4

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v2

    if-le v2, v9, :cond_4

    move v2, v8

    goto :goto_1

    :cond_4
    move v2, v7

    :goto_1
    iget-object v6, v4, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v6}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v6, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v5

    if-eqz v5, :cond_5

    invoke-virtual {v6}, Ljava/lang/String;->length()I

    move-result v5

    if-le v5, v9, :cond_5

    move v7, v8

    :cond_5
    if-eq v2, v7, :cond_6

    if-ge v2, v7, :cond_8

    goto :goto_2

    :cond_6
    iget-object v2, p0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    if-eqz v2, :cond_9

    invoke-virtual {v2, v4, v3}, Llyiahf/vczjk/yn;->o00Oo0(Llyiahf/vczjk/rm;Llyiahf/vczjk/rm;)Llyiahf/vczjk/rm;

    move-result-object v2

    if-ne v2, v4, :cond_7

    goto :goto_3

    :cond_7
    if-ne v2, v3, :cond_9

    :goto_2
    move-object v0, v1

    :cond_8
    :goto_3
    iget-object v1, v1, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_9
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v4}, Llyiahf/vczjk/rm;->o00oO0O()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3}, Llyiahf/vczjk/rm;->o00oO0O()Ljava/lang/String;

    move-result-object v3

    const-string v4, "Conflicting setter definitions for property \""

    const-string v5, "\": "

    const-string v6, " vs "

    invoke-static {v4, v1, v5, v2, v6}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a
    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rq;

    if-nez v1, :cond_b

    goto :goto_4

    :cond_b
    new-instance v3, Llyiahf/vczjk/rq;

    iget-boolean v8, v0, Llyiahf/vczjk/rq;->OooO0o0:Z

    iget-boolean v9, v0, Llyiahf/vczjk/rq;->OooO0o:Z

    const/4 v5, 0x0

    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0OO:Ljava/io/Serializable;

    move-object v6, v1

    check-cast v6, Llyiahf/vczjk/xa7;

    iget-boolean v7, v0, Llyiahf/vczjk/rq;->OooO0Oo:Z

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/rq;-><init>(Llyiahf/vczjk/pm;Llyiahf/vczjk/rq;Llyiahf/vczjk/xa7;ZZZ)V

    move-object v0, v3

    :goto_4
    iput-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    check-cast v4, Llyiahf/vczjk/rm;

    return-object v4
.end method

.method public final OooOOo0()Ljava/lang/Class;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOOOo()Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOoo()Llyiahf/vczjk/xa7;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->Oooo0o0()Llyiahf/vczjk/pm;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1
    :goto_0
    return-object v1
.end method

.method public final OooOo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    invoke-static {v0}, Llyiahf/vczjk/eh6;->OooOoo0(Llyiahf/vczjk/rq;)Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    invoke-static {v0}, Llyiahf/vczjk/eh6;->OooOoo0(Llyiahf/vczjk/rq;)Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    invoke-static {v0}, Llyiahf/vczjk/eh6;->OooOoo0(Llyiahf/vczjk/rq;)Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    invoke-static {v0}, Llyiahf/vczjk/eh6;->OooOoOO(Llyiahf/vczjk/rq;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final OooOo0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo00()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0O(Llyiahf/vczjk/xa7;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOo0:Llyiahf/vczjk/xa7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xa7;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final OooOo0o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOoO()Z
    .locals 2

    new-instance v0, Llyiahf/vczjk/uz5;

    const/16 v1, 0x1c

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/uz5;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/eh6;->Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOoO0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    invoke-static {v0}, Llyiahf/vczjk/eh6;->OooOoOO(Llyiahf/vczjk/rq;)Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    invoke-static {v0}, Llyiahf/vczjk/eh6;->OooOoOO(Llyiahf/vczjk/rq;)Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    invoke-static {v0}, Llyiahf/vczjk/eh6;->OooOoOO(Llyiahf/vczjk/rq;)Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    invoke-static {v0}, Llyiahf/vczjk/eh6;->OooOoOO(Llyiahf/vczjk/rq;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final Oooo000(Ljava/util/Set;Ljava/util/HashMap;Llyiahf/vczjk/rq;)V
    .locals 8

    move-object v0, p3

    :goto_0
    if-eqz v0, :cond_8

    iget-boolean v1, v0, Llyiahf/vczjk/rq;->OooO0Oo:Z

    if-eqz v1, :cond_6

    iget-object v1, v0, Llyiahf/vczjk/rq;->OooO0OO:Ljava/io/Serializable;

    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/xa7;

    if-nez v7, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {p2, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/eh6;

    if-nez v1, :cond_1

    new-instance v2, Llyiahf/vczjk/eh6;

    iget-object v3, p0, Llyiahf/vczjk/eh6;->OooOOOO:Llyiahf/vczjk/fc5;

    iget-object v4, p0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    iget-boolean v5, p0, Llyiahf/vczjk/eh6;->OooOOO:Z

    iget-object v6, p0, Llyiahf/vczjk/eh6;->OooOOo:Llyiahf/vczjk/xa7;

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/eh6;-><init>(Llyiahf/vczjk/fc5;Llyiahf/vczjk/yn;ZLlyiahf/vczjk/xa7;Llyiahf/vczjk/xa7;)V

    invoke-virtual {p2, v7, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-object v1, v2

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    if-ne p3, v2, :cond_2

    iget-object v2, v1, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/rq;->OooO0o(Llyiahf/vczjk/rq;)Llyiahf/vczjk/rq;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    goto :goto_2

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    if-ne p3, v2, :cond_3

    iget-object v2, v1, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/rq;->OooO0o(Llyiahf/vczjk/rq;)Llyiahf/vczjk/rq;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    goto :goto_2

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    if-ne p3, v2, :cond_4

    iget-object v2, v1, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/rq;->OooO0o(Llyiahf/vczjk/rq;)Llyiahf/vczjk/rq;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    goto :goto_2

    :cond_4
    iget-object v2, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-ne p3, v2, :cond_5

    iget-object v2, v1, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/rq;->OooO0o(Llyiahf/vczjk/rq;)Llyiahf/vczjk/rq;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    goto :goto_2

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "Internal error: mismatched accessors, property: "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_6
    :goto_1
    iget-boolean v1, v0, Llyiahf/vczjk/rq;->OooO0o0:Z

    if-nez v1, :cond_7

    :goto_2
    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rq;

    goto :goto_0

    :cond_7
    new-instance p2, Ljava/lang/IllegalStateException;

    new-instance p3, Ljava/lang/StringBuilder;

    const-string v1, "Conflicting/ambiguous property name definitions (implicit name \'"

    invoke-direct {p3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/eh6;->OooOOo0:Llyiahf/vczjk/xa7;

    invoke-virtual {p3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "\'): found multiple explicit names: "

    invoke-virtual {p3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, ", but also implicit accessor: "

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_8
    return-void
.end method

.method public final Oooo0OO(Llyiahf/vczjk/dh6;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    const/4 v1, 0x0

    if-eqz v0, :cond_3

    iget-boolean v0, p0, Llyiahf/vczjk/eh6;->OooOOO:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    invoke-interface {p1, v0}, Llyiahf/vczjk/dh6;->OooO(Llyiahf/vczjk/pm;)Ljava/lang/Object;

    move-result-object v1

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    invoke-interface {p1, v0}, Llyiahf/vczjk/dh6;->OooO(Llyiahf/vczjk/pm;)Ljava/lang/Object;

    move-result-object v1

    :cond_1
    if-nez v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    invoke-interface {p1, v0}, Llyiahf/vczjk/dh6;->OooO(Llyiahf/vczjk/pm;)Ljava/lang/Object;

    move-result-object v1

    :cond_2
    :goto_0
    if-nez v1, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/rq;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pm;

    invoke-interface {p1, v0}, Llyiahf/vczjk/dh6;->OooO(Llyiahf/vczjk/pm;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_3
    return-object v1
.end method

.method public final Oooo0o0()Llyiahf/vczjk/pm;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/eh6;->OooOOO:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOO0O()Llyiahf/vczjk/pm;

    move-result-object v0

    return-object v0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOO0o()Llyiahf/vczjk/vm;

    move-result-object v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOOo()Llyiahf/vczjk/rm;

    move-result-object v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->OooOOO()Llyiahf/vczjk/mm;

    move-result-object v0

    :cond_1
    if-nez v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/eb0;->OooOO0O()Llyiahf/vczjk/pm;

    move-result-object v0

    :cond_2
    return-object v0
.end method

.method public final compareTo(Ljava/lang/Object;)I
    .locals 1

    check-cast p1, Llyiahf/vczjk/eh6;

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-nez v0, :cond_1

    const/4 p1, -0x1

    return p1

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    if-eqz v0, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/eh6;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/eh6;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    move-result p1

    return p1
.end method

.method public final getFullName()Llyiahf/vczjk/xa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOo0:Llyiahf/vczjk/xa7;

    return-object v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/eh6;->OooOOo0:Llyiahf/vczjk/xa7;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[Property \'"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/eh6;->OooOOo0:Llyiahf/vczjk/xa7;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "\'; ctors: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/eh6;->OooOo00:Llyiahf/vczjk/rq;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", field(s): "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/eh6;->OooOOoo:Llyiahf/vczjk/rq;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", getter(s): "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/eh6;->OooOo0:Llyiahf/vczjk/rq;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", setter(s): "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/eh6;->OooOo0O:Llyiahf/vczjk/rq;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "]"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
