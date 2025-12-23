.class public final Llyiahf/vczjk/xf;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $handleReferencePoint:Llyiahf/vczjk/o4;

.field final synthetic $positionProvider:Llyiahf/vczjk/v86;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v86;Llyiahf/vczjk/o4;Llyiahf/vczjk/ze3;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xf;->$positionProvider:Llyiahf/vczjk/v86;

    iput-object p2, p0, Llyiahf/vczjk/xf;->$handleReferencePoint:Llyiahf/vczjk/o4;

    iput-object p3, p0, Llyiahf/vczjk/xf;->$content:Llyiahf/vczjk/ze3;

    iput p4, p0, Llyiahf/vczjk/xf;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object p2, p0, Llyiahf/vczjk/xf;->$positionProvider:Llyiahf/vczjk/v86;

    iget-object v0, p0, Llyiahf/vczjk/xf;->$handleReferencePoint:Llyiahf/vczjk/o4;

    iget-object v1, p0, Llyiahf/vczjk/xf;->$content:Llyiahf/vczjk/ze3;

    iget v2, p0, Llyiahf/vczjk/xf;->$$changed:I

    or-int/lit8 v2, v2, 0x1

    invoke-static {v2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v2

    invoke-static {p2, v0, v1, p1, v2}, Llyiahf/vczjk/nqa;->OooO0O0(Llyiahf/vczjk/v86;Llyiahf/vczjk/o4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
