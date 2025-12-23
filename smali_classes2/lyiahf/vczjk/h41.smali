.class public final Llyiahf/vczjk/h41;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J


# instance fields
.field private final elements:[Llyiahf/vczjk/or1;


# direct methods
.method public constructor <init>([Llyiahf/vczjk/or1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/h41;->elements:[Llyiahf/vczjk/or1;

    return-void
.end method

.method private final readResolve()Ljava/lang/Object;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/h41;->elements:[Llyiahf/vczjk/or1;

    sget-object v1, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v0, v3

    invoke-interface {v1, v4}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    return-object v1
.end method
