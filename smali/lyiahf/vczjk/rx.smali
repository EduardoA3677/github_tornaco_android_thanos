.class public final Llyiahf/vczjk/rx;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $alignment:Llyiahf/vczjk/n4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rx;->$alignment:Llyiahf/vczjk/n4;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p2, Llyiahf/vczjk/yn4;

    iget-object p2, p0, Llyiahf/vczjk/rx;->$alignment:Llyiahf/vczjk/n4;

    const/4 v0, 0x0

    check-cast p2, Llyiahf/vczjk/tb0;

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/tb0;->OooO00o(II)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method
