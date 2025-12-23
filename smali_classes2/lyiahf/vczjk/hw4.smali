.class public final Llyiahf/vczjk/hw4;
.super Llyiahf/vczjk/w02;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/vh6;


# static fields
.field public static final synthetic OooOo0o:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooOOo:Llyiahf/vczjk/dm5;

.field public final OooOOoo:Llyiahf/vczjk/hc3;

.field public final OooOo0:Llyiahf/vczjk/o45;

.field public final OooOo00:Llyiahf/vczjk/o45;

.field public final OooOo0O:Llyiahf/vczjk/pw4;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/hw4;

    const-string v2, "fragments"

    const-string v3, "getFragments()Ljava/util/List;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "empty"

    const-string v5, "getEmpty()Z"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/4 v2, 0x2

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/hw4;->OooOo0o:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/dm5;Llyiahf/vczjk/hc3;Llyiahf/vczjk/q45;)V
    .locals 3

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "storageManager"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    iget-object v1, p2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v2

    if-eqz v2, :cond_0

    sget-object v1, Llyiahf/vczjk/ic3;->OooO0o0:Llyiahf/vczjk/qt5;

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    :goto_0
    invoke-direct {p0, v0, v1}, Llyiahf/vczjk/w02;-><init>(Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;)V

    iput-object p1, p0, Llyiahf/vczjk/hw4;->OooOOo:Llyiahf/vczjk/dm5;

    iput-object p2, p0, Llyiahf/vczjk/hw4;->OooOOoo:Llyiahf/vczjk/hc3;

    new-instance p1, Llyiahf/vczjk/gw4;

    const/4 p2, 0x0

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/gw4;-><init>(Llyiahf/vczjk/hw4;I)V

    new-instance p2, Llyiahf/vczjk/o45;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p2, p0, Llyiahf/vczjk/hw4;->OooOo00:Llyiahf/vczjk/o45;

    new-instance p1, Llyiahf/vczjk/gw4;

    const/4 p2, 0x1

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/gw4;-><init>(Llyiahf/vczjk/hw4;I)V

    new-instance p2, Llyiahf/vczjk/o45;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p2, p0, Llyiahf/vczjk/hw4;->OooOo0:Llyiahf/vczjk/o45;

    new-instance p1, Llyiahf/vczjk/pw4;

    new-instance p2, Llyiahf/vczjk/gw4;

    const/4 v0, 0x2

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/gw4;-><init>(Llyiahf/vczjk/hw4;I)V

    invoke-direct {p1, p3, p2}, Llyiahf/vczjk/pw4;-><init>(Llyiahf/vczjk/w59;Llyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/hw4;->OooOo0O:Llyiahf/vczjk/pw4;

    return-void
.end method


# virtual methods
.method public final OooOO0o()Llyiahf/vczjk/v02;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/hw4;->OooOOoo:Llyiahf/vczjk/hc3;

    iget-object v1, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/hw4;->OooOOo:Llyiahf/vczjk/dm5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v0

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/z02;->OooOOoo(Llyiahf/vczjk/hw4;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    instance-of v0, p1, Llyiahf/vczjk/vh6;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/vh6;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    const/4 v0, 0x0

    if-nez p1, :cond_1

    return v0

    :cond_1
    check-cast p1, Llyiahf/vczjk/hw4;

    iget-object v1, p0, Llyiahf/vczjk/hw4;->OooOOoo:Llyiahf/vczjk/hc3;

    iget-object v2, p1, Llyiahf/vczjk/hw4;->OooOOoo:Llyiahf/vczjk/hc3;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/hw4;->OooOOo:Llyiahf/vczjk/dm5;

    iget-object p1, p1, Llyiahf/vczjk/hw4;->OooOOo:Llyiahf/vczjk/dm5;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    const/4 p1, 0x1

    return p1

    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/hw4;->OooOOo:Llyiahf/vczjk/dm5;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Llyiahf/vczjk/hw4;->OooOOoo:Llyiahf/vczjk/hc3;

    invoke-virtual {v1}, Llyiahf/vczjk/hc3;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
