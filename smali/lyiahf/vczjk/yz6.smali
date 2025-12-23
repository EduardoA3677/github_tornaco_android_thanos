.class public final Llyiahf/vczjk/yz6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $parentBounds:Llyiahf/vczjk/y14;

.field final synthetic $popupContentSize:J

.field final synthetic $popupPosition:Llyiahf/vczjk/gl7;

.field final synthetic $windowSize:J

.field final synthetic this$0:Llyiahf/vczjk/zz6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gl7;Llyiahf/vczjk/zz6;Llyiahf/vczjk/y14;JJ)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yz6;->$popupPosition:Llyiahf/vczjk/gl7;

    iput-object p2, p0, Llyiahf/vczjk/yz6;->this$0:Llyiahf/vczjk/zz6;

    iput-object p3, p0, Llyiahf/vczjk/yz6;->$parentBounds:Llyiahf/vczjk/y14;

    iput-wide p4, p0, Llyiahf/vczjk/yz6;->$windowSize:J

    iput-wide p6, p0, Llyiahf/vczjk/yz6;->$popupContentSize:J

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/yz6;->$popupPosition:Llyiahf/vczjk/gl7;

    iget-object v1, p0, Llyiahf/vczjk/yz6;->this$0:Llyiahf/vczjk/zz6;

    invoke-virtual {v1}, Llyiahf/vczjk/zz6;->getPositionProvider()Llyiahf/vczjk/c07;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/yz6;->$parentBounds:Llyiahf/vczjk/y14;

    iget-wide v4, p0, Llyiahf/vczjk/yz6;->$windowSize:J

    iget-object v1, p0, Llyiahf/vczjk/yz6;->this$0:Llyiahf/vczjk/zz6;

    invoke-virtual {v1}, Llyiahf/vczjk/zz6;->getParentLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v6

    iget-wide v7, p0, Llyiahf/vczjk/yz6;->$popupContentSize:J

    invoke-interface/range {v2 .. v8}, Llyiahf/vczjk/c07;->OooO00o(Llyiahf/vczjk/y14;JLlyiahf/vczjk/yn4;J)J

    move-result-wide v1

    iput-wide v1, v0, Llyiahf/vczjk/gl7;->element:J

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
