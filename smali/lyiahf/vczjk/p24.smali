.class public final synthetic Llyiahf/vczjk/p24;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/p24;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/p24;

    const-string v4, "min(II)I"

    const/4 v5, 0x1

    const/4 v1, 0x2

    const-class v2, Llyiahf/vczjk/ye5;

    const-string v3, "min"

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/p24;->OooOOO:Llyiahf/vczjk/p24;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    invoke-static {p1, p2}, Ljava/lang/Math;->min(II)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method
