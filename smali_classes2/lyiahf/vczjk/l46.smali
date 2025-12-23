.class public final Llyiahf/vczjk/l46;
.super Llyiahf/vczjk/dha;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/x58;

.field public final OooO0OO:Llyiahf/vczjk/g46;

.field public final OooO0Oo:Llyiahf/vczjk/eh7;

.field public final OooO0o:Llyiahf/vczjk/ss0;

.field public final OooO0o0:Llyiahf/vczjk/jj0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x58;Llyiahf/vczjk/g46;)V
    .locals 10

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/l46;->OooO0O0:Llyiahf/vczjk/x58;

    iput-object p2, p0, Llyiahf/vczjk/l46;->OooO0OO:Llyiahf/vczjk/g46;

    iget-object p2, p1, Llyiahf/vczjk/x58;->OooO0O0:Llyiahf/vczjk/mi;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p2, Llyiahf/vczjk/mi;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Ljava/util/LinkedHashMap;

    const-string v1, "keyword"

    invoke-interface {v0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_0

    const-string v2, ""

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/x58;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)V

    :cond_0
    iget-object p2, p2, Llyiahf/vczjk/mi;->OooOOOo:Ljava/lang/Object;

    check-cast p2, Ljava/util/LinkedHashMap;

    invoke-interface {p2, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_4

    iget-object p2, p1, Llyiahf/vczjk/x58;->OooO00o:Ljava/util/LinkedHashMap;

    invoke-virtual {p2, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_2

    invoke-interface {v0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    new-instance v2, Llyiahf/vczjk/w58;

    invoke-virtual {v0, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-direct {v2, v0}, Llyiahf/vczjk/m25;-><init>(Ljava/lang/Object;)V

    iput-object v1, v2, Llyiahf/vczjk/w58;->OooOO0o:Ljava/lang/String;

    iput-object p1, v2, Llyiahf/vczjk/w58;->OooOOO0:Llyiahf/vczjk/x58;

    goto :goto_0

    :cond_1
    new-instance v0, Llyiahf/vczjk/w58;

    invoke-direct {v0}, Llyiahf/vczjk/m25;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/w58;->OooOO0o:Ljava/lang/String;

    iput-object p1, v0, Llyiahf/vczjk/w58;->OooOOO0:Llyiahf/vczjk/x58;

    move-object v2, v0

    :goto_0
    invoke-interface {p2, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    check-cast v2, Llyiahf/vczjk/w58;

    new-instance p1, Llyiahf/vczjk/r73;

    const/4 p2, 0x0

    invoke-direct {p1, v2, p2}, Llyiahf/vczjk/r73;-><init>(Llyiahf/vczjk/m25;Llyiahf/vczjk/yo1;)V

    invoke-static {p1}, Llyiahf/vczjk/rs;->OooOO0O(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/lo0;

    move-result-object p1

    const/4 v0, -0x1

    invoke-static {p1, v0}, Llyiahf/vczjk/rs;->OooOO0(Llyiahf/vczjk/f43;I)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/k46;

    invoke-direct {v0, p2, p0}, Llyiahf/vczjk/k46;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/l46;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/rs;->OooooOO(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/et0;

    move-result-object p1

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/nn0;

    invoke-direct {v1, v0, p2}, Llyiahf/vczjk/nn0;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/yo1;)V

    new-instance v2, Llyiahf/vczjk/w43;

    invoke-direct {v2, p1, v1, p2}, Llyiahf/vczjk/w43;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V

    invoke-static {v2}, Llyiahf/vczjk/ll6;->OooOOOo(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/on0;

    const/4 v2, 0x3

    invoke-direct {v1, v2, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    const-string v3, "<this>"

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/r43;

    invoke-direct {v3, p1, v1, p2}, Llyiahf/vczjk/r43;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V

    new-instance p1, Llyiahf/vczjk/s48;

    invoke-direct {p1, v3}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v1, Llyiahf/vczjk/mn0;

    const/4 v3, 0x0

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/mn0;-><init>(Llyiahf/vczjk/s48;I)V

    new-instance p1, Llyiahf/vczjk/pn0;

    const/4 v3, 0x2

    invoke-direct {p1, v3, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v3, Llyiahf/vczjk/l53;

    invoke-direct {v3, v1, p1}, Llyiahf/vczjk/l53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V

    new-instance p1, Llyiahf/vczjk/qn0;

    invoke-direct {p1, v2, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v1, Llyiahf/vczjk/j53;

    invoke-direct {v1, v3, p1}, Llyiahf/vczjk/j53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)V

    sget-object v5, Llyiahf/vczjk/ql8;->OooO0O0:Llyiahf/vczjk/e86;

    invoke-static {v1}, Llyiahf/vczjk/dn8;->Oooo0O0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/ie;

    move-result-object p1

    iget v1, p1, Llyiahf/vczjk/ie;->OooO00o:I

    iget-object v2, p1, Llyiahf/vczjk/ie;->OooO0OO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/aj0;

    const/4 v3, 0x1

    invoke-static {v3, v1, v2}, Llyiahf/vczjk/zsa;->OooOO0O(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/zsa;->OooO0oo:Llyiahf/vczjk/h87;

    iget-object v1, p1, Llyiahf/vczjk/ie;->OooO0O0:Ljava/lang/Object;

    move-object v6, v1

    check-cast v6, Llyiahf/vczjk/f43;

    sget-object v1, Llyiahf/vczjk/ql8;->OooO00o:Llyiahf/vczjk/wp3;

    invoke-virtual {v5, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    sget-object v1, Llyiahf/vczjk/as1;->OooOOO0:Llyiahf/vczjk/as1;

    goto :goto_1

    :cond_3
    sget-object v1, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    :goto_1
    new-instance v4, Llyiahf/vczjk/p63;

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/p63;-><init>(Llyiahf/vczjk/rl8;Llyiahf/vczjk/f43;Llyiahf/vczjk/os5;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    iget-object p1, p1, Llyiahf/vczjk/ie;->OooO0Oo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/or1;

    invoke-static {v0, p1, v1, v4}, Llyiahf/vczjk/os9;->Oooo0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    new-instance p1, Llyiahf/vczjk/eh7;

    invoke-direct {p1, v7}, Llyiahf/vczjk/eh7;-><init>(Llyiahf/vczjk/os5;)V

    iput-object p1, p0, Llyiahf/vczjk/l46;->OooO0Oo:Llyiahf/vczjk/eh7;

    const/4 p1, 0x7

    const/4 v0, 0x0

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/l46;->OooO0o0:Llyiahf/vczjk/jj0;

    new-instance p2, Llyiahf/vczjk/ss0;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/ss0;-><init>(Llyiahf/vczjk/ui7;Z)V

    iput-object p2, p0, Llyiahf/vczjk/l46;->OooO0o:Llyiahf/vczjk/ss0;

    return-void

    :cond_4
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "StateFlow and LiveData are mutually exclusive for the same key. Please use either \'getMutableStateFlow\' or \'getLiveData\' for key \'keyword\', but not both."

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/String;)V
    .locals 3

    const-string v0, "keyword"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/l46;->OooO0O0:Llyiahf/vczjk/x58;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/x58;->OooO00o(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v2

    invoke-static {v2, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    return-void

    :cond_0
    invoke-virtual {v1, v0, p1}, Llyiahf/vczjk/x58;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method
