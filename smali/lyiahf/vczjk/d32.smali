.class public final Llyiahf/vczjk/d32;
.super Llyiahf/vczjk/lm6;
.source "SourceFile"


# static fields
.field public static final Oooo0:Llyiahf/vczjk/era;


# instance fields
.field public final Oooo00o:Llyiahf/vczjk/qs5;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ye1;->OooOOoo:Llyiahf/vczjk/ye1;

    sget-object v1, Llyiahf/vczjk/ke0;->Oooo00o:Llyiahf/vczjk/ke0;

    invoke-static {v1, v0}, Llyiahf/vczjk/vc6;->Oooo0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/era;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/d32;->Oooo0:Llyiahf/vczjk/era;

    return-void
.end method

.method public constructor <init>(IFLlyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/lm6;-><init>(FI)V

    invoke-static {p3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/d32;->Oooo00o:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooOO0o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/d32;->Oooo00o:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    return v0
.end method
