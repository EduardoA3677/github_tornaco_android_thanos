.class public final Llyiahf/vczjk/dqa;
.super Llyiahf/vczjk/eo6;
.source "SourceFile"


# static fields
.field public static final OooO0oo:Ljava/lang/String;


# instance fields
.field public final OooO0OO:Llyiahf/vczjk/oqa;

.field public final OooO0Oo:Ljava/util/List;

.field public final OooO0o:Ljava/util/ArrayList;

.field public final OooO0o0:Ljava/util/ArrayList;

.field public OooO0oO:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "WorkContinuationImpl"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/dqa;->OooO0oo:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/oqa;Ljava/util/List;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dqa;->OooO0OO:Llyiahf/vczjk/oqa;

    iput-object p2, p0, Llyiahf/vczjk/dqa;->OooO0Oo:Ljava/util/List;

    new-instance p1, Ljava/util/ArrayList;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v0

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/dqa;->OooO0o0:Ljava/util/ArrayList;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dqa;->OooO0o:Ljava/util/ArrayList;

    const/4 p1, 0x0

    :goto_0
    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v0

    if-ge p1, v0, :cond_0

    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/yqa;

    iget-object v0, v0, Llyiahf/vczjk/yqa;->OooO00o:Ljava/util/UUID;

    invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "id.toString()"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/dqa;->OooO0o0:Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v1, p0, Llyiahf/vczjk/dqa;->OooO0o:Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 p1, p1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public static OooOooo(Llyiahf/vczjk/dqa;Ljava/util/HashSet;)Z
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/dqa;->OooO0o0:Ljava/util/ArrayList;

    invoke-interface {p1, v0}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    invoke-static {p0}, Llyiahf/vczjk/dqa;->Oooo000(Llyiahf/vczjk/dqa;)Ljava/util/HashSet;

    move-result-object v0

    invoke-virtual {p1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-virtual {v0, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_1
    iget-object p0, p0, Llyiahf/vczjk/dqa;->OooO0o0:Ljava/util/ArrayList;

    invoke-interface {p1, p0}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    const/4 p0, 0x0

    return p0
.end method

.method public static Oooo000(Llyiahf/vczjk/dqa;)Ljava/util/HashSet;
    .locals 1

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-object v0
.end method
