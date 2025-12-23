.class public final synthetic Llyiahf/vczjk/gx4;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/gx4;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/gx4;

    const-string v4, "<init>(Landroid/view/View;)V"

    const/4 v5, 0x0

    const/4 v1, 0x1

    const-class v2, Llyiahf/vczjk/p04;

    const-string v3, "<init>"

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/gx4;->OooOOO:Llyiahf/vczjk/gx4;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Landroid/view/View;

    new-instance v0, Llyiahf/vczjk/p04;

    invoke-direct {v0, p1}, Llyiahf/vczjk/p04;-><init>(Landroid/view/View;)V

    return-object v0
.end method
