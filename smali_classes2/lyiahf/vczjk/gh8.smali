.class public final Llyiahf/vczjk/gh8;
.super Llyiahf/vczjk/o00O0OO0;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/gh8;


# instance fields
.field private final backing:Llyiahf/vczjk/eb5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/eb5;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/gh8;

    sget-object v1, Llyiahf/vczjk/eb5;->OooOOO0:Llyiahf/vczjk/eb5;

    sget-object v1, Llyiahf/vczjk/eb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-direct {v0, v1}, Llyiahf/vczjk/gh8;-><init>(Llyiahf/vczjk/eb5;)V

    sput-object v0, Llyiahf/vczjk/gh8;->OooOOO0:Llyiahf/vczjk/gh8;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/eb5;

    invoke-direct {v0}, Llyiahf/vczjk/eb5;-><init>()V

    invoke-direct {p0, v0}, Llyiahf/vczjk/gh8;-><init>(Llyiahf/vczjk/eb5;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/eb5;)V
    .locals 1

    const-string v0, "backing"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/util/AbstractSet;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    return-void
.end method

.method private final writeReplace()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOo00()Z

    move-result v0

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/jg8;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/jg8;-><init>(Ljava/util/AbstractCollection;I)V

    return-object v0

    :cond_0
    new-instance v0, Ljava/io/NotSerializableException;

    const-string v1, "The set cannot be serialized while it is being built."

    invoke-direct {v0, v1}, Ljava/io/NotSerializableException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->size()I

    move-result v0

    return v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/gh8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOO0O()Llyiahf/vczjk/eb5;

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->size()I

    move-result v0

    if-lez v0, :cond_0

    return-object p0

    :cond_0
    sget-object v0, Llyiahf/vczjk/gh8;->OooOOO0:Llyiahf/vczjk/gh8;

    return-object v0
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/eb5;->OooO(Ljava/lang/Object;)I

    move-result p1

    if-ltz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 1

    const-string v0, "elements"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOO0o()V

    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    move-result p1

    return p1
.end method

.method public final clear()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->clear()V

    return-void
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/eb5;->containsKey(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final isEmpty()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->isEmpty()Z

    move-result v0

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/bb5;

    const/4 v2, 0x1

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/bb5;-><init>(Llyiahf/vczjk/eb5;I)V

    return-object v1
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOO0o()V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/eb5;->OooOOo0(Ljava/lang/Object;)I

    move-result p1

    if-gez p1, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/eb5;->OooOo0o(I)V

    const/4 p1, 0x1

    return p1
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 1

    const-string v0, "elements"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOO0o()V

    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    move-result p1

    return p1
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 1

    const-string v0, "elements"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/gh8;->backing:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOO0o()V

    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->retainAll(Ljava/util/Collection;)Z

    move-result p1

    return p1
.end method
