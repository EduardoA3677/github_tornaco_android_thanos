.class public final Llyiahf/vczjk/vu8;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Llyiahf/vczjk/wu8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wu8;Llyiahf/vczjk/zo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vu8;->this$0:Llyiahf/vczjk/wu8;

    invoke-direct {p0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iput-object p1, p0, Llyiahf/vczjk/vu8;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/vu8;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/vu8;->label:I

    iget-object v0, p0, Llyiahf/vczjk/vu8;->this$0:Llyiahf/vczjk/wu8;

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v5, p0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/wu8;->OooO0O0(Llyiahf/vczjk/wu8;Llyiahf/vczjk/v98;FFLlyiahf/vczjk/su8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
