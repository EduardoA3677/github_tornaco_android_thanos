.class public abstract Llyiahf/vczjk/ya0;
.super Llyiahf/vczjk/m49;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;
.implements Llyiahf/vczjk/nr7;


# static fields
.field public static final OooOOOo:Llyiahf/vczjk/xa7;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public transient OooOOOO:Ljava/util/HashMap;

.field protected _anySetter:Llyiahf/vczjk/nh8;

.field protected _arrayDelegateDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _backRefs:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Llyiahf/vczjk/ph8;",
            ">;"
        }
    .end annotation
.end field

.field protected final _beanProperties:Llyiahf/vczjk/fb0;

.field protected final _beanType:Llyiahf/vczjk/x64;

.field protected _delegateDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected _externalTypeIdHandler:Llyiahf/vczjk/vu2;

.field protected final _ignorableProps:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field protected final _ignoreAllUnknown:Z

.field protected final _injectables:[Llyiahf/vczjk/jca;

.field protected final _needViewProcesing:Z

.field protected _nonStandardCreation:Z

.field protected final _objectIdReader:Llyiahf/vczjk/u66;

.field protected _propertyBasedCreator:Llyiahf/vczjk/oa7;

.field protected final _serializationShape:Llyiahf/vczjk/p94;

.field protected _unwrappedPropertyHandler:Llyiahf/vczjk/haa;

.field protected final _valueInstantiator:Llyiahf/vczjk/nca;

.field protected _vanillaProcessing:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/xa7;

    const/4 v1, 0x0

    const-string v2, "#temporary-name"

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/xa7;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/ya0;->OooOOOo:Llyiahf/vczjk/xa7;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ya0;)V
    .locals 1

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/ya0;-><init>(Llyiahf/vczjk/ya0;Z)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ya0;Ljava/util/Set;)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object p1, p1, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    check-cast p2, Ljava/util/Set;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fb0;->OooOOOO(Ljava/util/Set;)Llyiahf/vczjk/fb0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ya0;Llyiahf/vczjk/fb0;)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iget-boolean p2, p1, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iput-boolean p2, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-boolean p2, p1, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iput-boolean p2, p0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iget-boolean p2, p1, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iput-boolean p2, p0, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iget-boolean p1, p1, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    iput-boolean p1, p0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ya0;Llyiahf/vczjk/u66;)V
    .locals 2

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    new-instance v0, Llyiahf/vczjk/y66;

    sget-object v1, Llyiahf/vczjk/wa7;->OooOOO:Llyiahf/vczjk/wa7;

    invoke-direct {v0, p2, v1}, Llyiahf/vczjk/y66;-><init>(Llyiahf/vczjk/u66;Llyiahf/vczjk/wa7;)V

    iget-object p1, p1, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fb0;->OooOOO(Llyiahf/vczjk/y66;)Llyiahf/vczjk/fb0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ya0;Llyiahf/vczjk/wt5;)V
    .locals 5

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-boolean v0, p1, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iput-boolean v0, p0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    if-eqz v0, :cond_2

    new-instance v1, Ljava/util/ArrayList;

    iget-object v0, v0, Llyiahf/vczjk/haa;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ph8;

    iget-object v3, v2, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v3}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p2, v3}, Llyiahf/vczjk/wt5;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ph8;->OooOooo(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v3

    if-eqz v3, :cond_0

    invoke-virtual {v3, p2}, Llyiahf/vczjk/e94;->OooOOOo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/e94;

    move-result-object v4

    if-eq v4, v3, :cond_0

    invoke-virtual {v2, v4}, Llyiahf/vczjk/ph8;->Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;

    move-result-object v2

    :cond_0
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    new-instance v0, Llyiahf/vczjk/haa;

    invoke-direct {v0, v1}, Llyiahf/vczjk/haa;-><init>(Ljava/util/ArrayList;)V

    :cond_2
    iget-object v1, p1, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/fb0;->OooOO0o(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/fb0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iget-boolean p2, p1, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iput-boolean p2, p0, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iget-object p1, p1, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iput-object p1, p0, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ya0;Z)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iget-object v0, p1, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iput-boolean p2, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-boolean p2, p1, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iput-boolean p2, p0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    iget-boolean p2, p1, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iput-boolean p2, p0, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iget-object p2, p1, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iput-object p2, p0, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iget-boolean p1, p1, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    iput-boolean p1, p0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/za0;Llyiahf/vczjk/h90;Llyiahf/vczjk/fb0;Ljava/util/HashMap;Ljava/util/HashSet;ZZ)V
    .locals 2

    iget-object v0, p2, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iget-object v0, p2, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/za0;->OooO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/nca;

    iput-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object p3, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    iput-object p4, p0, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    iput-object p5, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iput-boolean p6, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    iget-object p3, p1, Llyiahf/vczjk/za0;->OooOO0O:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/nh8;

    iput-object p3, p0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    iget-object p3, p1, Llyiahf/vczjk/za0;->OooO0o:Ljava/lang/Object;

    check-cast p3, Ljava/util/ArrayList;

    const/4 p4, 0x0

    if-eqz p3, :cond_1

    invoke-virtual {p3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p5

    if-eqz p5, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p3}, Ljava/util/ArrayList;->size()I

    move-result p5

    new-array p5, p5, [Llyiahf/vczjk/jca;

    invoke-virtual {p3, p5}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p3

    check-cast p3, [Llyiahf/vczjk/jca;

    goto :goto_1

    :cond_1
    :goto_0
    move-object p3, p4

    :goto_1
    iput-object p3, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    iget-object p1, p1, Llyiahf/vczjk/za0;->OooOO0:Ljava/io/Serializable;

    check-cast p1, Llyiahf/vczjk/u66;

    iput-object p1, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object p5, p0, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    const/4 p6, 0x1

    const/4 v1, 0x0

    if-nez p5, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOO0()Z

    move-result p5

    if-nez p5, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooO0o()Z

    move-result p5

    if-nez p5, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooO()Z

    move-result p5

    if-nez p5, :cond_2

    goto :goto_2

    :cond_2
    move p5, v1

    goto :goto_3

    :cond_3
    :goto_2
    move p5, p6

    :goto_3
    iput-boolean p5, p0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    invoke-virtual {p2}, Llyiahf/vczjk/h90;->OooO0Oo()Llyiahf/vczjk/q94;

    move-result-object p2

    if-nez p2, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object p4

    :goto_4
    iput-object p4, p0, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    iput-boolean p7, p0, Llyiahf/vczjk/ya0;->_needViewProcesing:Z

    iget-boolean p2, p0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    if-nez p2, :cond_5

    if-nez p3, :cond_5

    if-nez p7, :cond_5

    if-nez p1, :cond_5

    goto :goto_5

    :cond_5
    move p6, v1

    :goto_5
    iput-boolean p6, p0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    return-void
.end method

.method public static OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/x64;Llyiahf/vczjk/gn;)Llyiahf/vczjk/e94;
    .locals 6

    new-instance v0, Llyiahf/vczjk/cb0;

    sget-object v5, Llyiahf/vczjk/wa7;->OooOOOO:Llyiahf/vczjk/wa7;

    sget-object v1, Llyiahf/vczjk/ya0;->OooOOOo:Llyiahf/vczjk/xa7;

    const/4 v3, 0x0

    move-object v2, p1

    move-object v4, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/cb0;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/pm;Llyiahf/vczjk/wa7;)V

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u3a;

    if-nez p1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p2, v2, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ec5;->OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/h90;

    move-result-object p2

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v1

    iget-object p2, p2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v1, p1, p2, v2}, Llyiahf/vczjk/yn;->OoooOOO(Llyiahf/vczjk/fc5;Llyiahf/vczjk/hm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooOO0()Llyiahf/vczjk/b5a;

    move-result-object v1

    const/4 p2, 0x0

    if-nez v1, :cond_1

    move-object p1, p2

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/fc5;->OooOooo()Llyiahf/vczjk/k99;

    move-result-object v3

    invoke-virtual {v3, p1, p2}, Llyiahf/vczjk/k99;->OooO0OO(Llyiahf/vczjk/t72;Llyiahf/vczjk/hm;)Ljava/util/ArrayList;

    move-result-object p2

    :cond_1
    check-cast v1, Llyiahf/vczjk/e59;

    invoke-virtual {v1, p1, v2, p2}, Llyiahf/vczjk/e59;->OooO00o(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;Ljava/util/ArrayList;)Llyiahf/vczjk/v3a;

    move-result-object p1

    :cond_2
    :goto_0
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/e94;

    if-nez p2, :cond_3

    invoke-virtual {p0, v2, v0}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object p0

    goto :goto_1

    :cond_3
    invoke-virtual {p0, p2, v0, v2}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p0

    :goto_1
    if-eqz p1, :cond_4

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u3a;->OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/q5a;

    invoke-direct {p2, p1, p0}, Llyiahf/vczjk/q5a;-><init>(Llyiahf/vczjk/u3a;Llyiahf/vczjk/e94;)V

    return-object p2

    :cond_4
    return-object p0
.end method

.method public static o00oO0o(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;)V
    .locals 1

    :goto_0
    instance-of v0, p0, Ljava/lang/reflect/InvocationTargetException;

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object p0

    goto :goto_0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    if-eqz p3, :cond_2

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo0:Llyiahf/vczjk/w72;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p3

    if-eqz p3, :cond_1

    goto :goto_1

    :cond_1
    const/4 p3, 0x0

    goto :goto_2

    :cond_2
    :goto_1
    const/4 p3, 0x1

    :goto_2
    instance-of v0, p0, Ljava/io/IOException;

    if-eqz v0, :cond_4

    if-eqz p3, :cond_3

    instance-of p3, p0, Llyiahf/vczjk/ib4;

    if-eqz p3, :cond_3

    goto :goto_3

    :cond_3
    check-cast p0, Ljava/io/IOException;

    throw p0

    :cond_4
    if-nez p3, :cond_5

    invoke-static {p0}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    :cond_5
    :goto_3
    sget p3, Llyiahf/vczjk/na4;->OooOOO:I

    new-instance p3, Llyiahf/vczjk/ma4;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p3}, Llyiahf/vczjk/na4;->OooO0oo(Ljava/lang/Throwable;Llyiahf/vczjk/ma4;)Llyiahf/vczjk/na4;

    move-result-object p0

    throw p0
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/o0OoO00O;
    .locals 1

    sget-object v0, Llyiahf/vczjk/o0OoO00O;->OooOOOO:Llyiahf/vczjk/o0OoO00O;

    return-object v0
.end method

.method public final OooO00o(Llyiahf/vczjk/v72;)V
    .locals 25

    move-object/from16 v0, p0

    move-object/from16 v2, p1

    iget-object v1, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v1}, Llyiahf/vczjk/nca;->OooO0o()Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v2}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v4

    invoke-virtual {v1, v4}, Llyiahf/vczjk/nca;->OooOoO(Llyiahf/vczjk/t72;)[Llyiahf/vczjk/ph8;

    move-result-object v1

    iget-object v4, v0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    if-eqz v4, :cond_2

    array-length v4, v1

    const/4 v5, 0x0

    :goto_0
    if-ge v5, v4, :cond_2

    aget-object v6, v1, v5

    iget-object v8, v0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    iget-object v6, v6, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v6}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v6

    invoke-interface {v8, v6}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_0

    aget-object v6, v1, v5

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOo()V

    :cond_0
    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :cond_2
    iget-object v4, v0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v4}, Llyiahf/vczjk/fb0;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_3
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_7

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ph8;

    invoke-virtual {v5}, Llyiahf/vczjk/ph8;->OooOOoo()Z

    move-result v6

    if-nez v6, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v6

    if-eqz v6, :cond_4

    invoke-interface {v5}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v8

    invoke-virtual {v6, v8}, Llyiahf/vczjk/yn;->OooO(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v6

    if-eqz v6, :cond_4

    invoke-interface {v5}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/mc4;->OooOo0(Ljava/lang/Object;)Llyiahf/vczjk/gp1;

    move-result-object v6

    invoke-virtual {v2}, Llyiahf/vczjk/v72;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-object v8, v6

    check-cast v8, Llyiahf/vczjk/j74;

    iget-object v8, v8, Llyiahf/vczjk/j74;->OooO00o:Llyiahf/vczjk/x64;

    invoke-virtual {v2, v8}, Llyiahf/vczjk/v72;->o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v9

    new-instance v10, Llyiahf/vczjk/k49;

    invoke-direct {v10, v6, v8, v9}, Llyiahf/vczjk/k49;-><init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)V

    goto :goto_2

    :cond_4
    const/4 v10, 0x0

    :goto_2
    if-nez v10, :cond_5

    iget-object v6, v5, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/v72;->o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v10

    :cond_5
    invoke-virtual {v5, v10}, Llyiahf/vczjk/ph8;->Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;

    move-result-object v6

    iget-object v8, v0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v8, v5, v6}, Llyiahf/vczjk/fb0;->OooOOO0(Llyiahf/vczjk/ph8;Llyiahf/vczjk/ph8;)V

    if-eqz v1, :cond_3

    array-length v8, v1

    const/4 v9, 0x0

    :goto_3
    if-ge v9, v8, :cond_3

    aget-object v10, v1, v9

    if-ne v10, v5, :cond_6

    aput-object v6, v1, v9

    goto :goto_1

    :cond_6
    add-int/lit8 v9, v9, 0x1

    goto :goto_3

    :cond_7
    iget-object v4, v0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v4}, Llyiahf/vczjk/fb0;->iterator()Ljava/util/Iterator;

    move-result-object v4

    const/4 v8, 0x0

    const/4 v9, 0x0

    :cond_8
    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    const/4 v10, 0x1

    if-eqz v5, :cond_1d

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ph8;

    invoke-virtual {v5}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v6

    iget-object v11, v5, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    invoke-virtual {v2, v6, v5, v11}, Llyiahf/vczjk/v72;->o000000(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v6

    invoke-virtual {v5, v6}, Llyiahf/vczjk/ph8;->Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOOO()Ljava/lang/String;

    move-result-object v11

    if-nez v11, :cond_9

    const/16 v16, 0x0

    const/16 v17, 0x0

    goto :goto_5

    :cond_9
    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v12

    invoke-virtual {v12, v11}, Llyiahf/vczjk/e94;->OooO0oo(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object v12

    if-eqz v12, :cond_1c

    iget-object v13, v0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v14, v12, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iget-object v15, v6, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    invoke-virtual {v15}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v15

    const/16 v16, 0x0

    invoke-virtual {v14}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    const/16 v17, 0x0

    invoke-virtual {v13}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v7

    invoke-virtual {v3, v7}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_1b

    new-instance v3, Llyiahf/vczjk/xa5;

    invoke-direct {v3, v6, v11, v12, v15}, Llyiahf/vczjk/xa5;-><init>(Llyiahf/vczjk/ph8;Ljava/lang/String;Llyiahf/vczjk/ph8;Z)V

    move-object v6, v3

    :goto_5
    nop

    instance-of v3, v6, Llyiahf/vczjk/xa5;

    if-nez v3, :cond_c

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOOo()Llyiahf/vczjk/t66;

    move-result-object v3

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v7

    if-nez v7, :cond_a

    move-object/from16 v7, v16

    goto :goto_6

    :cond_a
    invoke-virtual {v7}, Llyiahf/vczjk/e94;->OooOO0o()Llyiahf/vczjk/u66;

    move-result-object v7

    :goto_6
    if-nez v3, :cond_b

    if-nez v7, :cond_b

    goto :goto_7

    :cond_b
    new-instance v7, Llyiahf/vczjk/w66;

    invoke-direct {v7, v6, v3}, Llyiahf/vczjk/w66;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/t66;)V

    move-object v6, v7

    :cond_c
    :goto_7
    invoke-interface {v6}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v3

    if-eqz v3, :cond_e

    invoke-virtual {v2}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v7

    invoke-virtual {v7, v3}, Llyiahf/vczjk/yn;->OoooOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/wt5;

    move-result-object v3

    if-eqz v3, :cond_e

    instance-of v7, v6, Llyiahf/vczjk/rs1;

    if-nez v7, :cond_d

    goto :goto_8

    :cond_d
    iget-object v1, v0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v3, v6, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v3}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Cannot define Creator property \""

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\" as `@JsonUnwrapped`: combination not yet supported"

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v16

    :cond_e
    move-object/from16 v3, v16

    :goto_8
    if-eqz v3, :cond_10

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v7

    invoke-virtual {v7, v3}, Llyiahf/vczjk/e94;->OooOOOo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/e94;

    move-result-object v3

    if-eq v3, v7, :cond_10

    if-eqz v3, :cond_10

    invoke-virtual {v6, v3}, Llyiahf/vczjk/ph8;->Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;

    move-result-object v3

    if-nez v9, :cond_f

    new-instance v5, Llyiahf/vczjk/haa;

    invoke-direct {v5}, Llyiahf/vczjk/haa;-><init>()V

    move-object v9, v5

    :cond_f
    iget-object v5, v9, Llyiahf/vczjk/haa;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v5, v0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/fb0;->OooOO0O(Llyiahf/vczjk/ph8;)V

    goto/16 :goto_4

    :cond_10
    invoke-virtual {v6}, Llyiahf/vczjk/lh1;->OooO0O0()Llyiahf/vczjk/wa7;

    move-result-object v3

    iget-object v7, v3, Llyiahf/vczjk/wa7;->OooOOO0:Llyiahf/vczjk/pc0;

    if-eqz v7, :cond_13

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v11

    invoke-virtual {v2}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v12

    invoke-virtual {v11, v12}, Llyiahf/vczjk/e94;->OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;

    move-result-object v12

    iget-boolean v13, v7, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-nez v12, :cond_11

    if-eqz v13, :cond_12

    goto :goto_9

    :cond_11
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v12

    if-nez v12, :cond_12

    if-nez v13, :cond_14

    invoke-virtual {v2, v11}, Llyiahf/vczjk/v72;->oo0o0Oo(Llyiahf/vczjk/e94;)V

    goto :goto_9

    :cond_12
    sget-object v11, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v2, v11}, Llyiahf/vczjk/v72;->o0000O00(Llyiahf/vczjk/gc5;)Z

    move-result v11

    iget-object v7, v7, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/pm;

    invoke-virtual {v7, v11}, Llyiahf/vczjk/pm;->oo000o(Z)V

    instance-of v11, v6, Llyiahf/vczjk/qh8;

    if-nez v11, :cond_13

    new-instance v11, Llyiahf/vczjk/mi5;

    invoke-direct {v11, v6, v7}, Llyiahf/vczjk/mi5;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/pm;)V

    move-object v6, v11

    :cond_13
    iget-object v3, v3, Llyiahf/vczjk/wa7;->_valueNulls:Llyiahf/vczjk/d56;

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v7

    invoke-static {v2, v6, v3, v7}, Llyiahf/vczjk/m49;->OooOoO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/d56;Llyiahf/vczjk/e94;)Llyiahf/vczjk/u46;

    move-result-object v3

    if-eqz v3, :cond_14

    invoke-virtual {v6, v3}, Llyiahf/vczjk/ph8;->OooOooO(Llyiahf/vczjk/u46;)Llyiahf/vczjk/ph8;

    move-result-object v6

    :cond_14
    :goto_9
    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v3

    instance-of v7, v3, Llyiahf/vczjk/ya0;

    if-eqz v7, :cond_17

    check-cast v3, Llyiahf/vczjk/ya0;

    iget-object v3, v3, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v3}, Llyiahf/vczjk/nca;->OooO()Z

    move-result v3

    if-nez v3, :cond_17

    iget-object v3, v6, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/vy0;->OooOOO(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v7

    if-eqz v7, :cond_17

    iget-object v11, v0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v11}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v11

    if-ne v7, v11, :cond_17

    invoke-virtual {v3}, Ljava/lang/Class;->getConstructors()[Ljava/lang/reflect/Constructor;

    move-result-object v3

    array-length v11, v3

    move/from16 v12, v17

    :goto_a
    if-ge v12, v11, :cond_17

    aget-object v13, v3, v12

    invoke-virtual {v13}, Ljava/lang/reflect/Constructor;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v14

    array-length v15, v14

    if-ne v15, v10, :cond_16

    aget-object v14, v14, v17

    invoke-virtual {v7, v14}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_16

    iget-object v3, v2, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v3}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v3

    if-eqz v3, :cond_15

    sget-object v3, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/v72;->o0000O00(Llyiahf/vczjk/gc5;)Z

    move-result v3

    invoke-static {v13, v3}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_15
    new-instance v3, Llyiahf/vczjk/yz3;

    invoke-direct {v3, v6, v13}, Llyiahf/vczjk/yz3;-><init>(Llyiahf/vczjk/ph8;Ljava/lang/reflect/Constructor;)V

    move-object v6, v3

    goto :goto_b

    :cond_16
    add-int/lit8 v12, v12, 0x1

    goto :goto_a

    :cond_17
    :goto_b
    if-eq v6, v5, :cond_19

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v3, v5, v6}, Llyiahf/vczjk/fb0;->OooOOO0(Llyiahf/vczjk/ph8;Llyiahf/vczjk/ph8;)V

    if-eqz v1, :cond_19

    array-length v3, v1

    move/from16 v7, v17

    :goto_c
    if-ge v7, v3, :cond_19

    aget-object v10, v1, v7

    if-ne v10, v5, :cond_18

    aput-object v6, v1, v7

    goto :goto_d

    :cond_18
    add-int/lit8 v7, v7, 0x1

    goto :goto_c

    :cond_19
    :goto_d
    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOo00()Z

    move-result v3

    if-eqz v3, :cond_8

    invoke-virtual {v6}, Llyiahf/vczjk/ph8;->OooOOo()Llyiahf/vczjk/u3a;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/u3a;->OooOO0()Llyiahf/vczjk/kc4;

    move-result-object v5

    sget-object v7, Llyiahf/vczjk/kc4;->OooOOOo:Llyiahf/vczjk/kc4;

    if-ne v5, v7, :cond_8

    if-nez v8, :cond_1a

    iget-object v5, v0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    new-instance v7, Llyiahf/vczjk/uqa;

    invoke-direct {v7, v5}, Llyiahf/vczjk/uqa;-><init>(Llyiahf/vczjk/x64;)V

    move-object v8, v7

    :cond_1a
    iget-object v5, v8, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v5, Ljava/util/ArrayList;

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v7

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    new-instance v10, Llyiahf/vczjk/uu2;

    invoke-direct {v10, v6, v3}, Llyiahf/vczjk/uu2;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/u3a;)V

    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v5, v6, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v5}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v8, v5, v7}, Llyiahf/vczjk/uqa;->OooO0oo(Ljava/lang/String;Ljava/lang/Integer;)V

    invoke-virtual {v3}, Llyiahf/vczjk/u3a;->OooO0oo()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v8, v3, v7}, Llyiahf/vczjk/uqa;->OooO0oo(Ljava/lang/String;Ljava/lang/Integer;)V

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v3, v6}, Llyiahf/vczjk/fb0;->OooOO0O(Llyiahf/vczjk/ph8;)V

    goto/16 :goto_4

    :cond_1b
    iget-object v1, v0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v14}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v13}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v4

    const-string v5, "Cannot handle managed/back reference \'"

    const-string v6, "\': back reference type ("

    const-string v7, ") not compatible with managed type ("

    invoke-static {v5, v11, v6, v3, v7}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, ")"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v16

    :cond_1c
    const/16 v16, 0x0

    iget-object v1, v0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v3, v6, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    filled-new-array {v11, v3}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "Cannot handle managed/back reference \'%s\': no back reference property found from type %s"

    invoke-static {v4, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v16

    :cond_1d
    const/16 v16, 0x0

    const/16 v17, 0x0

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    if-eqz v3, :cond_1f

    iget-object v4, v3, Llyiahf/vczjk/nh8;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-eqz v4, :cond_1e

    goto :goto_e

    :cond_1e
    iget-object v4, v3, Llyiahf/vczjk/nh8;->_type:Llyiahf/vczjk/x64;

    iget-object v5, v3, Llyiahf/vczjk/nh8;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {v2, v4, v5}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v23

    new-instance v18, Llyiahf/vczjk/nh8;

    iget-object v4, v3, Llyiahf/vczjk/nh8;->_property:Llyiahf/vczjk/db0;

    iget-object v5, v3, Llyiahf/vczjk/nh8;->_setter:Llyiahf/vczjk/pm;

    iget-object v6, v3, Llyiahf/vczjk/nh8;->_type:Llyiahf/vczjk/x64;

    iget-object v7, v3, Llyiahf/vczjk/nh8;->_keyDeserializer:Llyiahf/vczjk/ti4;

    iget-object v3, v3, Llyiahf/vczjk/nh8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    move-object/from16 v24, v3

    move-object/from16 v19, v4

    move-object/from16 v20, v5

    move-object/from16 v21, v6

    move-object/from16 v22, v7

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/nh8;-><init>(Llyiahf/vczjk/db0;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;Llyiahf/vczjk/ti4;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;)V

    move-object/from16 v3, v18

    iput-object v3, v0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    :cond_1f
    :goto_e
    iget-object v3, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v3}, Llyiahf/vczjk/nca;->OooOO0()Z

    move-result v3

    if-eqz v3, :cond_21

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v3}, Llyiahf/vczjk/nca;->OooOoO0()Llyiahf/vczjk/x64;

    move-result-object v3

    if-eqz v3, :cond_20

    iget-object v4, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v4}, Llyiahf/vczjk/nca;->OooOo()Llyiahf/vczjk/gn;

    move-result-object v4

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/ya0;->OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/x64;Llyiahf/vczjk/gn;)Llyiahf/vczjk/e94;

    move-result-object v3

    iput-object v3, v0, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    goto :goto_f

    :cond_20
    iget-object v1, v0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    filled-new-array {v1, v3}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "Invalid delegate-creator definition for %s: value instantiator (%s) returned true for \'canCreateUsingDelegate()\', but null for \'getDelegateType()\'"

    invoke-static {v4, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v16

    :cond_21
    :goto_f
    iget-object v3, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v3}, Llyiahf/vczjk/nca;->OooO0oo()Z

    move-result v3

    if-eqz v3, :cond_23

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v3}, Llyiahf/vczjk/nca;->OooOo0O()Llyiahf/vczjk/x64;

    move-result-object v3

    if-eqz v3, :cond_22

    iget-object v4, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v4}, Llyiahf/vczjk/nca;->OooOo0()Llyiahf/vczjk/gn;

    move-result-object v4

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/ya0;->OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/x64;Llyiahf/vczjk/gn;)Llyiahf/vczjk/e94;

    move-result-object v3

    iput-object v3, v0, Llyiahf/vczjk/ya0;->_arrayDelegateDeserializer:Llyiahf/vczjk/e94;

    goto :goto_10

    :cond_22
    iget-object v1, v0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    filled-new-array {v1, v3}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "Invalid delegate-creator definition for %s: value instantiator (%s) returned true for \'canCreateUsingArrayDelegate()\', but null for \'getArrayDelegateType()\'"

    invoke-static {v4, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v16

    :cond_23
    :goto_10
    if-eqz v1, :cond_26

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    iget-object v4, v0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    array-length v5, v1

    new-array v6, v5, [Llyiahf/vczjk/ph8;

    const/4 v7, 0x0

    :goto_11
    if-ge v7, v5, :cond_25

    aget-object v11, v1, v7

    invoke-virtual {v11}, Llyiahf/vczjk/ph8;->OooOOoo()Z

    move-result v12

    if-nez v12, :cond_24

    invoke-virtual {v11}, Llyiahf/vczjk/ph8;->OooOo0o()Z

    move-result v12

    if-nez v12, :cond_24

    invoke-virtual {v11}, Llyiahf/vczjk/ph8;->getType()Llyiahf/vczjk/x64;

    move-result-object v12

    invoke-virtual {v2, v12, v11}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v12

    invoke-virtual {v11, v12}, Llyiahf/vczjk/ph8;->Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;

    move-result-object v11

    :cond_24
    aput-object v11, v6, v7

    add-int/lit8 v7, v7, 0x1

    goto :goto_11

    :cond_25
    new-instance v1, Llyiahf/vczjk/oa7;

    iget-boolean v5, v4, Llyiahf/vczjk/fb0;->_caseInsensitive:Z

    move-object v4, v6

    const/4 v6, 0x1

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/oa7;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/nca;[Llyiahf/vczjk/ph8;ZZ)V

    iput-object v1, v0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    :cond_26
    if-eqz v8, :cond_29

    iget-object v1, v0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    iget-object v2, v8, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v3

    new-array v4, v3, [Llyiahf/vczjk/uu2;

    move/from16 v5, v17

    :goto_12
    if-ge v5, v3, :cond_28

    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/uu2;

    iget-object v7, v6, Llyiahf/vczjk/uu2;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v1, v7}, Llyiahf/vczjk/fb0;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object v7

    if-eqz v7, :cond_27

    iput-object v7, v6, Llyiahf/vczjk/uu2;->OooO0Oo:Llyiahf/vczjk/ph8;

    :cond_27
    aput-object v6, v4, v5

    add-int/lit8 v5, v5, 0x1

    goto :goto_12

    :cond_28
    new-instance v1, Llyiahf/vczjk/vu2;

    iget-object v2, v8, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/util/HashMap;

    iget-object v3, v8, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/x64;

    invoke-direct {v1, v3, v4, v2}, Llyiahf/vczjk/vu2;-><init>(Llyiahf/vczjk/x64;[Llyiahf/vczjk/uu2;Ljava/util/HashMap;)V

    iput-object v1, v0, Llyiahf/vczjk/ya0;->_externalTypeIdHandler:Llyiahf/vczjk/vu2;

    iput-boolean v10, v0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    :cond_29
    iput-object v9, v0, Llyiahf/vczjk/ya0;->_unwrappedPropertyHandler:Llyiahf/vczjk/haa;

    if-eqz v9, :cond_2a

    iput-boolean v10, v0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    :cond_2a
    iget-boolean v1, v0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    if-eqz v1, :cond_2b

    iget-boolean v1, v0, Llyiahf/vczjk/ya0;->_nonStandardCreation:Z

    if-nez v1, :cond_2b

    move v7, v10

    goto :goto_13

    :cond_2b
    move/from16 v7, v17

    :goto_13
    iput-boolean v7, v0, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 13

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz p2, :cond_0

    if-eqz v1, :cond_0

    const/4 v3, 0x1

    goto :goto_0

    :cond_0
    move v3, v2

    :goto_0
    const/4 v4, 0x0

    if-eqz v3, :cond_1

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v3

    goto :goto_1

    :cond_1
    move-object v3, v4

    :goto_1
    if-eqz v3, :cond_6

    invoke-virtual {v1, v3}, Llyiahf/vczjk/yn;->OooOoO0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/t66;

    move-result-object v5

    if-eqz v5, :cond_6

    invoke-virtual {v1, v3, v5}, Llyiahf/vczjk/yn;->OooOoO(Llyiahf/vczjk/u34;Llyiahf/vczjk/t66;)Llyiahf/vczjk/t66;

    move-result-object v0

    iget-object v5, v0, Llyiahf/vczjk/t66;->OooO0O0:Ljava/lang/Class;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mc4;->OoooOO0(Llyiahf/vczjk/t66;)V

    const-class v6, Llyiahf/vczjk/s66;

    iget-object v9, v0, Llyiahf/vczjk/t66;->OooO00o:Llyiahf/vczjk/xa7;

    if-ne v5, v6, :cond_5

    invoke-virtual {v9}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v2

    iget-object v5, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    if-nez v5, :cond_2

    move-object v5, v4

    goto :goto_2

    :cond_2
    invoke-virtual {v5, v2}, Llyiahf/vczjk/fb0;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object v5

    :goto_2
    if-nez v5, :cond_3

    iget-object v6, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    if-eqz v6, :cond_3

    invoke-virtual {v6, v2}, Llyiahf/vczjk/oa7;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object v5

    :cond_3
    if-eqz v5, :cond_4

    iget-object v2, v5, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    new-instance v6, Llyiahf/vczjk/qa7;

    iget-object v0, v0, Llyiahf/vczjk/t66;->OooO0Oo:Ljava/lang/Class;

    invoke-direct {v6, v0}, Llyiahf/vczjk/q66;-><init>(Ljava/lang/Class;)V

    move-object v12, v5

    :goto_3
    move-object v8, v2

    move-object v10, v6

    goto :goto_4

    :cond_4
    iget-object p2, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Invalid Object Id definition for "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, ": cannot find property with name \'"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, "\'"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v4

    :cond_5
    invoke-virtual {p1, v5}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v5

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-class v6, Llyiahf/vczjk/p66;

    invoke-static {v6, v5}, Llyiahf/vczjk/a4a;->OooOOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)[Llyiahf/vczjk/x64;

    move-result-object v5

    aget-object v2, v5, v2

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mc4;->OoooO(Llyiahf/vczjk/t66;)Llyiahf/vczjk/p66;

    move-result-object v6

    move-object v12, v4

    goto :goto_3

    :goto_4
    invoke-virtual {p1, v8}, Llyiahf/vczjk/v72;->o00o0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v11

    new-instance v7, Llyiahf/vczjk/u66;

    invoke-direct/range {v7 .. v12}, Llyiahf/vczjk/u66;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/p66;Llyiahf/vczjk/e94;Llyiahf/vczjk/ph8;)V

    move-object v0, v7

    :cond_6
    if-eqz v0, :cond_7

    iget-object v2, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    if-eq v0, v2, :cond_7

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ya0;->oo000o(Llyiahf/vczjk/u66;)Llyiahf/vczjk/ya0;

    move-result-object v0

    goto :goto_5

    :cond_7
    move-object v0, p0

    :goto_5
    if-eqz v3, :cond_a

    invoke-virtual {v1, v3}, Llyiahf/vczjk/yn;->Oooo00o(Llyiahf/vczjk/u34;)Llyiahf/vczjk/ba4;

    move-result-object v1

    if-eqz v1, :cond_a

    invoke-virtual {v1}, Llyiahf/vczjk/ba4;->OooO0O0()Ljava/util/Set;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Set;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_9

    iget-object v3, v0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    if-eqz v3, :cond_8

    invoke-interface {v3}, Ljava/util/Set;->isEmpty()Z

    move-result v5

    if-nez v5, :cond_8

    new-instance v5, Ljava/util/HashSet;

    invoke-direct {v5, v2}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    invoke-interface {v5, v3}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    move-object v2, v5

    :cond_8
    invoke-virtual {v0, v2}, Llyiahf/vczjk/ya0;->o00o0O(Ljava/util/Set;)Llyiahf/vczjk/ya0;

    move-result-object v0

    :cond_9
    invoke-virtual {v1}, Llyiahf/vczjk/ba4;->OooO0Oo()Z

    move-result v1

    if-eqz v1, :cond_a

    iget-boolean v1, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    if-nez v1, :cond_a

    invoke-virtual {v0}, Llyiahf/vczjk/ya0;->o00ooo()Llyiahf/vczjk/ya0;

    move-result-object v0

    :cond_a
    iget-object v1, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    if-eqz p2, :cond_b

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object p1

    invoke-interface {p2, v1, p1}, Llyiahf/vczjk/db0;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/fc5;)Llyiahf/vczjk/q94;

    move-result-object p1

    goto :goto_6

    :cond_b
    invoke-virtual {p1, v1}, Llyiahf/vczjk/v72;->o0ooOOo(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    :goto_6
    if-eqz p1, :cond_e

    invoke-virtual {p1}, Llyiahf/vczjk/q94;->OooOO0()Z

    move-result p2

    if-eqz p2, :cond_c

    invoke-virtual {p1}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v4

    :cond_c
    sget-object p2, Llyiahf/vczjk/n94;->OooOOO:Llyiahf/vczjk/n94;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q94;->OooO0O0(Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object p1

    if-eqz p1, :cond_e

    iget-object p2, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-boolean v1, p2, Llyiahf/vczjk/fb0;->_caseInsensitive:Z

    if-ne v1, p1, :cond_d

    move-object v1, p2

    goto :goto_7

    :cond_d
    new-instance v1, Llyiahf/vczjk/fb0;

    invoke-direct {v1, p2, p1}, Llyiahf/vczjk/fb0;-><init>(Llyiahf/vczjk/fb0;Z)V

    :goto_7
    if-eq v1, p2, :cond_e

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ya0;->o00Ooo(Llyiahf/vczjk/fb0;)Llyiahf/vczjk/ya0;

    move-result-object v0

    :cond_e
    if-nez v4, :cond_f

    iget-object v4, p0, Llyiahf/vczjk/ya0;->_serializationShape:Llyiahf/vczjk/p94;

    :cond_f
    sget-object p1, Llyiahf/vczjk/p94;->OooOOOo:Llyiahf/vczjk/p94;

    if-ne v4, p1, :cond_10

    invoke-virtual {v0}, Llyiahf/vczjk/ya0;->OoooOoo()Llyiahf/vczjk/ya0;

    move-result-object p1

    return-object p1

    :cond_10
    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    if-eqz v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OooO0Oo()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000()Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    invoke-virtual {p0, p1, p2, v0}, Llyiahf/vczjk/ya0;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V

    throw v1

    :cond_1
    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/gc4;->OooO0o0()Z

    move-result v2

    if-nez v2, :cond_3

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    :cond_2
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object v0, v0, Llyiahf/vczjk/u66;->generator:Llyiahf/vczjk/p66;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_1

    :cond_3
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/ya0;->OooooOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    throw v1

    :cond_4
    :goto_1
    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oo(Ljava/lang/String;)Llyiahf/vczjk/ph8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_backRefs:Ljava/util/Map;

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ph8;

    return-object p1
.end method

.method public final OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 1

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception v0

    invoke-static {p1, v0}, Llyiahf/vczjk/vy0;->OooOo0o(Llyiahf/vczjk/v72;Ljava/io/IOException;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOO0O()Ljava/util/Collection;
    .locals 3

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v1}, Llyiahf/vczjk/fb0;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ph8;

    iget-object v2, v2, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v2}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    return-object v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/u66;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    return-object v0
.end method

.method public final OooOOO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooOOO0()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method

.method public abstract OooOOOo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/e94;
.end method

.method public final OoooO()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final OoooOOO()Llyiahf/vczjk/e94;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_arrayDelegateDeserializer:Llyiahf/vczjk/e94;

    :cond_0
    return-object v0
.end method

.method public abstract OoooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
.end method

.method public final OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object v0, v0, Llyiahf/vczjk/u66;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0}, Llyiahf/vczjk/e94;->OooOOO0()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    if-eq v1, v2, :cond_3

    new-instance v1, Llyiahf/vczjk/tt9;

    invoke-direct {v1, p2, p1}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    instance-of p1, p3, Ljava/lang/String;

    if-nez p1, :cond_2

    instance-of p1, p3, Ljava/lang/Long;

    if-nez p1, :cond_1

    instance-of p1, p3, Ljava/lang/Integer;

    if-eqz p1, :cond_0

    check-cast p3, Ljava/lang/Integer;

    sget-object p1, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    invoke-virtual {v1, p3, p1}, Llyiahf/vczjk/tt9;->o000O0O(Ljava/lang/Object;Llyiahf/vczjk/gc4;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v1, p3}, Llyiahf/vczjk/tt9;->o000O0oo(Ljava/lang/Object;)V

    goto :goto_0

    :cond_1
    check-cast p3, Ljava/lang/Long;

    sget-object p1, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    invoke-virtual {v1, p3, p1}, Llyiahf/vczjk/tt9;->o000O0O(Ljava/lang/Object;Llyiahf/vczjk/gc4;)V

    goto :goto_0

    :cond_2
    check-cast p3, Ljava/lang/String;

    invoke-virtual {v1, p3}, Llyiahf/vczjk/tt9;->o0000ooO(Ljava/lang/String;)V

    :goto_0
    iget-object p1, v1, Llyiahf/vczjk/tt9;->OooOOO:Llyiahf/vczjk/l66;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/tt9;->o000O0o0(Llyiahf/vczjk/l66;)Llyiahf/vczjk/rt9;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p3

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object p1, p1, Llyiahf/vczjk/u66;->generator:Llyiahf/vczjk/p66;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o00Ooo(Ljava/lang/Object;Llyiahf/vczjk/p66;)Llyiahf/vczjk/bh7;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    throw p1
.end method

.method public abstract OoooOoo()Llyiahf/vczjk/ya0;
.end method

.method public final Ooooo00(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OoooOOO()Llyiahf/vczjk/e94;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v1}, Llyiahf/vczjk/nca;->OooO0O0()Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_0
    return-object p2

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo0o:Llyiahf/vczjk/gc4;

    if-ne p2, v0, :cond_2

    const/4 p2, 0x1

    goto :goto_0

    :cond_2
    const/4 p2, 0x0

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/nca;->OooOO0o(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final Ooooo0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000oO()Llyiahf/vczjk/db4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/db4;->OooOOo0:Llyiahf/vczjk/db4;

    if-eq v0, v1, :cond_2

    sget-object v1, Llyiahf/vczjk/db4;->OooOOOo:Llyiahf/vczjk/db4;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OoooOOO()Llyiahf/vczjk/e94;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v2, "no suitable creator method found to deserialize from Number value (%s)"

    invoke-virtual {p1, v0, v1, v2, p2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1

    :cond_2
    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OoooOOO()Llyiahf/vczjk/e94;

    move-result-object v0

    if-eqz v0, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v1}, Llyiahf/vczjk/nca;->OooO0OO()Z

    move-result v1

    if-nez v1, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v0, :cond_3

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_3
    return-object p2

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0ooOO0()D

    move-result-wide v1

    invoke-virtual {v0, p1, v1, v2}, Llyiahf/vczjk/nca;->OooOOO0(Llyiahf/vczjk/v72;D)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooooO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    const/4 v1, 0x0

    if-nez v0, :cond_8

    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OoooOOO()Llyiahf/vczjk/e94;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000oO()Llyiahf/vczjk/db4;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/db4;->OooOOO0:Llyiahf/vczjk/db4;

    if-ne v2, v3, :cond_2

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v1}, Llyiahf/vczjk/nca;->OooO0Oo()Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_0
    return-object p2

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result p2

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/nca;->OooOOO(Llyiahf/vczjk/v72;I)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    sget-object v3, Llyiahf/vczjk/db4;->OooOOO:Llyiahf/vczjk/db4;

    if-ne v2, v3, :cond_5

    if-eqz v0, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v1}, Llyiahf/vczjk/nca;->OooO0Oo()Z

    move-result v1

    if-nez v1, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v0, :cond_3

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_3
    return-object p2

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000Ooo()J

    move-result-wide v1

    invoke-virtual {v0, p1, v1, v2}, Llyiahf/vczjk/nca;->OooOOOO(Llyiahf/vczjk/v72;J)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_5
    if-eqz v0, :cond_7

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v0, :cond_6

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_6
    return-object p2

    :cond_7
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p2

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    const-string v3, "no suitable creator method found to deserialize from Number value (%s)"

    invoke-virtual {p1, v0, v2, v3, p2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    throw v1

    :cond_8
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ya0;->OooooOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    throw v1
.end method

.method public final OooooOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/u66;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object v0, v0, Llyiahf/vczjk/u66;->generator:Llyiahf/vczjk/p66;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/v72;->o00Ooo(Ljava/lang/Object;Llyiahf/vczjk/p66;)Llyiahf/vczjk/bh7;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooooOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OoooOOO()Llyiahf/vczjk/e94;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_0
    return-object p2

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    if-eqz v0, :cond_2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ya0;->OoooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    iget-object p2, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    invoke-virtual {p2}, Ljava/lang/Class;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-nez v0, :cond_4

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOo00(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_3

    move-object v0, v2

    goto :goto_0

    :cond_3
    invoke-virtual {p2}, Ljava/lang/Class;->getEnclosingClass()Ljava/lang/Class;

    move-result-object v0

    :goto_0
    if-eqz v0, :cond_4

    const/4 v0, 0x1

    goto :goto_1

    :cond_4
    move v0, v1

    :goto_1
    if-eqz v0, :cond_5

    const-string v0, "non-static inner classes like this can only by instantiated using default, no-argument constructor"

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {p1, p2, v2, v0, v1}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    throw v2

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    const-string v3, "cannot deserialize from Object value (no delegate- or property-based Creator)"

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {p1, p2, v0, v3, v1}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    throw v2
.end method

.method public final Oooooo()Llyiahf/vczjk/nca;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    return-object v0
.end method

.method public final Oooooo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_objectIdReader:Llyiahf/vczjk/u66;

    if-nez v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OoooOOO()Llyiahf/vczjk/e94;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v1}, Llyiahf/vczjk/nca;->OooO0oO()Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ya0;->o00Oo0(Llyiahf/vczjk/v72;)V

    :cond_0
    return-object p2

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/nca;->OooOOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ya0;->OooooOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OoooooO(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V
    .locals 7

    sget-object v0, Llyiahf/vczjk/w72;->OooOo0O:Llyiahf/vczjk/w72;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p3

    if-eqz p3, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OooOO0O()Ljava/util/Collection;

    move-result-object v6

    sget p3, Llyiahf/vczjk/gu3;->OooOOOo:I

    instance-of p3, p1, Ljava/lang/Class;

    if-eqz p3, :cond_0

    move-object p3, p1

    check-cast p3, Ljava/lang/Class;

    :goto_0
    move-object v4, p3

    goto :goto_1

    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p3

    goto :goto_0

    :goto_1
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p3

    const-string v0, "Ignored field \""

    const-string v1, "\" (class "

    const-string v2, ") encountered; mapper configured not to allow this"

    invoke-static {v0, p2, v1, p3, v2}, Llyiahf/vczjk/ii5;->OooOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    new-instance v0, Llyiahf/vczjk/gu3;

    invoke-virtual {p4}, Llyiahf/vczjk/eb4;->OoooOO0()Llyiahf/vczjk/ia4;

    move-result-object v3

    move-object v5, p2

    move-object v1, p4

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ra7;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/ia4;Ljava/lang/Class;Ljava/lang/String;Ljava/util/Collection;)V

    new-instance p2, Llyiahf/vczjk/ma4;

    invoke-direct {p2, p1, v5}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Llyiahf/vczjk/na4;->OooO0o(Llyiahf/vczjk/ma4;)V

    throw v0

    :cond_1
    move-object v1, p4

    invoke-virtual {v1}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    return-void
.end method

.method public final Ooooooo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;Llyiahf/vczjk/tt9;)Ljava/lang/Object;
    .locals 4

    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/ya0;->OooOOOO:Ljava/util/HashMap;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/ky0;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-direct {v1, v2}, Llyiahf/vczjk/ky0;-><init>(Ljava/lang/Class;)V

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/e94;

    :goto_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    if-eqz v0, :cond_1

    goto :goto_3

    :cond_1
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o00o0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    if-eqz v0, :cond_3

    monitor-enter p0

    :try_start_1
    iget-object v1, p0, Llyiahf/vczjk/ya0;->OooOOOO:Ljava/util/HashMap;

    if-nez v1, :cond_2

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/ya0;->OooOOOO:Ljava/util/HashMap;

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_2
    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/ya0;->OooOOOO:Ljava/util/HashMap;

    new-instance v2, Llyiahf/vczjk/ky0;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-direct {v2, v3}, Llyiahf/vczjk/ky0;-><init>(Ljava/lang/Class;)V

    invoke-virtual {v1, v2, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    monitor-exit p0

    goto :goto_3

    :goto_2
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :cond_3
    :goto_3
    if-eqz v0, :cond_6

    if-eqz p4, :cond_4

    invoke-virtual {p4}, Llyiahf/vczjk/tt9;->o00000o0()V

    iget-object v1, p4, Llyiahf/vczjk/tt9;->OooOOO:Llyiahf/vczjk/l66;

    invoke-virtual {p4, v1}, Llyiahf/vczjk/tt9;->o000O0o0(Llyiahf/vczjk/l66;)Llyiahf/vczjk/rt9;

    move-result-object p4

    invoke-virtual {p4}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {v0, p4, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    :cond_4
    if-eqz p1, :cond_5

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_5
    return-object p3

    :cond_6
    if-eqz p4, :cond_7

    invoke-virtual {p0, p2, p3, p4}, Llyiahf/vczjk/ya0;->o0OoOo0(Llyiahf/vczjk/v72;Ljava/lang/Object;Llyiahf/vczjk/tt9;)V

    :cond_7
    if-eqz p1, :cond_8

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_8
    return-object p3

    :catchall_1
    move-exception p1

    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw p1
.end method

.method public final o00O0O(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    if-eqz v0, :cond_0

    invoke-interface {v0, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ya0;->OoooooO(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    if-eqz v0, :cond_1

    :try_start_0
    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/nh8;->OooO0O0(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p4

    invoke-static {p4, p1, p2, p3}, Llyiahf/vczjk/ya0;->o00oO0o(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;)V

    const/4 p1, 0x0

    throw p1

    :cond_1
    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ya0;->ooOO(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    return-void
.end method

.method public final o00Oo0(Llyiahf/vczjk/v72;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_injectables:[Llyiahf/vczjk/jca;

    array-length v1, v0

    if-gtz v1, :cond_0

    return-void

    :cond_0
    const/4 v1, 0x0

    aget-object v0, v0, v1

    iget-object v0, v0, Llyiahf/vczjk/jca;->_valueId:Ljava/lang/Object;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->ooOO(Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public abstract o00Ooo(Llyiahf/vczjk/fb0;)Llyiahf/vczjk/ya0;
.end method

.method public abstract o00o0O(Ljava/util/Set;)Llyiahf/vczjk/ya0;
.end method

.method public final o00oO0O(Ljava/lang/Exception;Llyiahf/vczjk/v72;)V
    .locals 1

    :goto_0
    instance-of v0, p1, Ljava/lang/reflect/InvocationTargetException;

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    instance-of v0, p1, Ljava/io/IOException;

    if-nez v0, :cond_3

    if-eqz p2, :cond_2

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    :cond_2
    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    const/4 p1, 0x0

    throw p1

    :cond_3
    check-cast p1, Ljava/io/IOException;

    throw p1
.end method

.method public abstract o00ooo()Llyiahf/vczjk/ya0;
.end method

.method public final o0OoOo0(Llyiahf/vczjk/v72;Ljava/lang/Object;Llyiahf/vczjk/tt9;)V
    .locals 2

    invoke-virtual {p3}, Llyiahf/vczjk/tt9;->o00000o0()V

    iget-object v0, p3, Llyiahf/vczjk/tt9;->OooOOO:Llyiahf/vczjk/l66;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/tt9;->o000O0o0(Llyiahf/vczjk/l66;)Llyiahf/vczjk/rt9;

    move-result-object p3

    :goto_0
    invoke-virtual {p3}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-eq v0, v1, :cond_0

    invoke-virtual {p3}, Llyiahf/vczjk/rt9;->OoooOoo()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p3}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p2, v0, p1, p3}, Llyiahf/vczjk/ya0;->ooOO(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public abstract oo000o(Llyiahf/vczjk/u66;)Llyiahf/vczjk/ya0;
.end method

.method public final ooOO(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    if-eqz v0, :cond_0

    invoke-virtual {p4}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    if-eqz v0, :cond_1

    invoke-interface {v0, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ya0;->OoooooO(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    :cond_1
    if-nez p1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OooOOO0()Ljava/lang/Class;

    move-result-object p1

    :cond_2
    invoke-virtual {p3, p4, p0, p1, p2}, Llyiahf/vczjk/v72;->o00000O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/m49;Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method
