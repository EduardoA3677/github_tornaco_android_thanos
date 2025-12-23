.class public final Llyiahf/vczjk/rq2;
.super Llyiahf/vczjk/dp8;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/n3a;

.field public final OooOOOO:Llyiahf/vczjk/oq2;

.field public final OooOOOo:Llyiahf/vczjk/tq2;

.field public final OooOOo:Z

.field public final OooOOo0:Ljava/util/List;

.field public final OooOOoo:[Ljava/lang/String;

.field public final OooOo00:Ljava/lang/String;


# direct methods
.method public varargs constructor <init>(Llyiahf/vczjk/n3a;Llyiahf/vczjk/oq2;Llyiahf/vczjk/tq2;Ljava/util/List;Z[Ljava/lang/String;)V
    .locals 1

    const-string v0, "kind"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "arguments"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "formatParams"

    invoke-static {p6, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rq2;->OooOOO:Llyiahf/vczjk/n3a;

    iput-object p2, p0, Llyiahf/vczjk/rq2;->OooOOOO:Llyiahf/vczjk/oq2;

    iput-object p3, p0, Llyiahf/vczjk/rq2;->OooOOOo:Llyiahf/vczjk/tq2;

    iput-object p4, p0, Llyiahf/vczjk/rq2;->OooOOo0:Ljava/util/List;

    iput-boolean p5, p0, Llyiahf/vczjk/rq2;->OooOOo:Z

    iput-object p6, p0, Llyiahf/vczjk/rq2;->OooOOoo:[Ljava/lang/String;

    invoke-virtual {p3}, Llyiahf/vczjk/tq2;->OooO00o()Ljava/lang/String;

    move-result-object p1

    array-length p2, p6

    invoke-static {p6, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    array-length p3, p2

    invoke-static {p2, p3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    invoke-static {p1, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/rq2;->OooOo00:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rq2;->OooOOOO:Llyiahf/vczjk/oq2;

    return-object v0
.end method

.method public final o000000()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rq2;->OooOOO:Llyiahf/vczjk/n3a;

    return-object v0
.end method

.method public final o000000o()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/rq2;->OooOOo:Z

    return v0
.end method

.method public final o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public final o00000Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/iaa;
    .locals 1

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public final o00000o0(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/iaa;
    .locals 1

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public final o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 1

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public final o0000Ooo(Z)Llyiahf/vczjk/dp8;
    .locals 7

    new-instance v0, Llyiahf/vczjk/rq2;

    iget-object v1, p0, Llyiahf/vczjk/rq2;->OooOOoo:[Ljava/lang/String;

    array-length v2, v1

    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    move-object v6, v1

    check-cast v6, [Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/rq2;->OooOOO:Llyiahf/vczjk/n3a;

    iget-object v2, p0, Llyiahf/vczjk/rq2;->OooOOOO:Llyiahf/vczjk/oq2;

    iget-object v3, p0, Llyiahf/vczjk/rq2;->OooOOOo:Llyiahf/vczjk/tq2;

    iget-object v4, p0, Llyiahf/vczjk/rq2;->OooOOo0:Ljava/util/List;

    move v5, p1

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/rq2;-><init>(Llyiahf/vczjk/n3a;Llyiahf/vczjk/oq2;Llyiahf/vczjk/tq2;Ljava/util/List;Z[Ljava/lang/String;)V

    return-object v0
.end method

.method public final o00ooo()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rq2;->OooOOo0:Ljava/util/List;

    return-object v0
.end method

.method public final o0OOO0o()Llyiahf/vczjk/d3a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    return-object v0
.end method
