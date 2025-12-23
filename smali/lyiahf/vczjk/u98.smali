.class public final Llyiahf/vczjk/u98;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ug6;


# instance fields
.field public final OooOOO:Ljava/util/ArrayList;

.field public final OooOOO0:I

.field public OooOOOO:Ljava/lang/Float;

.field public OooOOOo:Ljava/lang/Float;

.field public OooOOo:Llyiahf/vczjk/b98;

.field public OooOOo0:Llyiahf/vczjk/b98;


# direct methods
.method public constructor <init>(ILjava/util/ArrayList;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/u98;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/u98;->OooOOO:Ljava/util/ArrayList;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/u98;->OooOOOO:Ljava/lang/Float;

    iput-object p1, p0, Llyiahf/vczjk/u98;->OooOOOo:Ljava/lang/Float;

    iput-object p1, p0, Llyiahf/vczjk/u98;->OooOOo0:Llyiahf/vczjk/b98;

    iput-object p1, p0, Llyiahf/vczjk/u98;->OooOOo:Llyiahf/vczjk/b98;

    return-void
.end method


# virtual methods
.method public final OooOOOo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u98;->OooOOO:Ljava/util/ArrayList;

    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result v0

    return v0
.end method
