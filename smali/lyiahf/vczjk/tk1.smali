.class public final Llyiahf/vczjk/tk1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0o0:Ljava/lang/String;


# instance fields
.field public final OooO00o:Landroid/content/Context;

.field public final OooO0O0:Llyiahf/vczjk/vp3;

.field public final OooO0OO:I

.field public final OooO0Oo:Llyiahf/vczjk/aqa;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "ConstraintsCmdHandler"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/tk1;->OooO0o0:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/vp3;ILlyiahf/vczjk/bd9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tk1;->OooO00o:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/tk1;->OooO0O0:Llyiahf/vczjk/vp3;

    iput p3, p0, Llyiahf/vczjk/tk1;->OooO0OO:I

    iget-object p1, p4, Llyiahf/vczjk/bd9;->OooOOo0:Llyiahf/vczjk/oqa;

    iget-object p1, p1, Llyiahf/vczjk/oqa;->OooOo0:Llyiahf/vczjk/qx9;

    new-instance p2, Llyiahf/vczjk/aqa;

    invoke-direct {p2, p1}, Llyiahf/vczjk/aqa;-><init>(Llyiahf/vczjk/qx9;)V

    iput-object p2, p0, Llyiahf/vczjk/tk1;->OooO0Oo:Llyiahf/vczjk/aqa;

    return-void
.end method
