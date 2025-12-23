.class public final Llyiahf/vczjk/vl7;
.super Llyiahf/vczjk/tl7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/y54;


# instance fields
.field public final OooO0O0:[Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qt5;[Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/tl7;-><init>(Llyiahf/vczjk/qt5;)V

    iput-object p2, p0, Llyiahf/vczjk/vl7;->OooO0O0:[Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/util/ArrayList;
    .locals 7

    new-instance v0, Ljava/util/ArrayList;

    iget-object v1, p0, Llyiahf/vczjk/vl7;->OooO0O0:[Ljava/lang/Object;

    array-length v2, v1

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    array-length v2, v1

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_4

    aget-object v4, v1, v3

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/rl7;->OooO00o:Ljava/util/List;

    const-class v6, Ljava/lang/Enum;

    invoke-virtual {v6, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    const/4 v6, 0x0

    if-eqz v5, :cond_0

    new-instance v5, Llyiahf/vczjk/hm7;

    check-cast v4, Ljava/lang/Enum;

    invoke-direct {v5, v6, v4}, Llyiahf/vczjk/hm7;-><init>(Llyiahf/vczjk/qt5;Ljava/lang/Enum;)V

    goto :goto_1

    :cond_0
    instance-of v5, v4, Ljava/lang/annotation/Annotation;

    if-eqz v5, :cond_1

    new-instance v5, Llyiahf/vczjk/ul7;

    check-cast v4, Ljava/lang/annotation/Annotation;

    invoke-direct {v5, v6, v4}, Llyiahf/vczjk/ul7;-><init>(Llyiahf/vczjk/qt5;Ljava/lang/annotation/Annotation;)V

    goto :goto_1

    :cond_1
    instance-of v5, v4, [Ljava/lang/Object;

    if-eqz v5, :cond_2

    new-instance v5, Llyiahf/vczjk/vl7;

    check-cast v4, [Ljava/lang/Object;

    invoke-direct {v5, v6, v4}, Llyiahf/vczjk/vl7;-><init>(Llyiahf/vczjk/qt5;[Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    instance-of v5, v4, Ljava/lang/Class;

    if-eqz v5, :cond_3

    new-instance v5, Llyiahf/vczjk/dm7;

    check-cast v4, Ljava/lang/Class;

    invoke-direct {v5, v6, v4}, Llyiahf/vczjk/dm7;-><init>(Llyiahf/vczjk/qt5;Ljava/lang/Class;)V

    goto :goto_1

    :cond_3
    new-instance v5, Llyiahf/vczjk/jm7;

    invoke-direct {v5, v6, v4}, Llyiahf/vczjk/jm7;-><init>(Llyiahf/vczjk/qt5;Ljava/lang/Object;)V

    :goto_1
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_4
    return-object v0
.end method
