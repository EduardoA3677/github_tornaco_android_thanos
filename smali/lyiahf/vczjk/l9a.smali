.class public final Llyiahf/vczjk/l9a;
.super Llyiahf/vczjk/na4;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field private _roid:Llyiahf/vczjk/bh7;

.field private _unresolvedIds:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/m9a;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb4;)V
    .locals 1

    const-string v0, "Unresolved forward references for: "

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;)V

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/l9a;->_unresolvedIds:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Class;Llyiahf/vczjk/ia4;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/l9a;->_unresolvedIds:Ljava/util/List;

    new-instance v1, Llyiahf/vczjk/m9a;

    invoke-direct {v1, p1, p2, p3}, Llyiahf/vczjk/m9a;-><init>(Ljava/lang/Object;Ljava/lang/Class;Llyiahf/vczjk/ia4;)V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooOO0()Llyiahf/vczjk/bh7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/l9a;->_roid:Llyiahf/vczjk/bh7;

    return-object v0
.end method

.method public final getMessage()Ljava/lang/String;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/na4;->OooO0Oo()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/l9a;->_unresolvedIds:Ljava/util/List;

    if-nez v1, :cond_0

    return-object v0

    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/l9a;->_unresolvedIds:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/m9a;

    invoke-virtual {v2}, Llyiahf/vczjk/m9a;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    const-string v2, ", "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    :cond_2
    const/16 v0, 0x2e

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
