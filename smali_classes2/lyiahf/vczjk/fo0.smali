.class public final Llyiahf/vczjk/fo0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/fo0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/fo0;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/fo0;->OooOOO0:Llyiahf/vczjk/fo0;

    return-void
.end method

.method private readResolve()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/fo0;->OooOOO0:Llyiahf/vczjk/fo0;

    return-object v0
.end method
