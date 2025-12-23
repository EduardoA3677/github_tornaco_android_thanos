.class public final Llyiahf/vczjk/k76;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/k76;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public final characterEscapes:Llyiahf/vczjk/xt0;

.field public final prettyPrinter:Llyiahf/vczjk/u37;

.field public final rootValueSeparator:Llyiahf/vczjk/fg8;

.field public final schema:Llyiahf/vczjk/zb3;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/k76;

    const/4 v1, 0x0

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/k76;-><init>(Llyiahf/vczjk/u37;Llyiahf/vczjk/fg8;)V

    sput-object v0, Llyiahf/vczjk/k76;->OooOOO0:Llyiahf/vczjk/k76;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/u37;Llyiahf/vczjk/fg8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/k76;->prettyPrinter:Llyiahf/vczjk/u37;

    iput-object p2, p0, Llyiahf/vczjk/k76;->rootValueSeparator:Llyiahf/vczjk/fg8;

    return-void
.end method
